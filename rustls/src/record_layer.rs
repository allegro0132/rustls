use alloc::boxed::Box;
use core::cmp::min;

use crate::crypto::cipher::{InboundOpaqueMessage, MessageDecrypter, MessageEncrypter};
use crate::error::Error;
use crate::log::trace;
use crate::msgs::message::{InboundPlainMessage, OutboundOpaqueMessage, OutboundPlainMessage};

#[derive(PartialEq)]
enum DirectionState {
    /// No keying material.
    Invalid,

    /// Keying material present, but not yet in use.
    Prepared,

    /// Keying material in use.
    Active,
}

/// Record layer that tracks decryption and encryption keys.
pub(crate) struct RecordLayer {
    message_encrypter: Box<dyn MessageEncrypter>,
    message_decrypter: Box<dyn MessageDecrypter>,
    pending_encryption: Option<Box<dyn crate::crypto::cipher::PendingEncryption>>,
    pending_decryption: Option<Box<dyn crate::crypto::cipher::PendingDecryption>>,
    decryption_waker: Option<core::task::Waker>,
    write_seq_max: u64,
    write_seq: u64,
    read_seq: u64,
    has_decrypted: bool,
    encrypt_state: DirectionState,
    decrypt_state: DirectionState,

    // Message encrypted with other keys may be encountered, so failures
    // should be swallowed by the caller.  This struct tracks the amount
    // of message size this is allowed for.
    trial_decryption_len: Option<usize>,
}

impl RecordLayer {
    /// Create new record layer with no keys.
    pub(crate) fn new() -> Self {
        Self {
            message_encrypter: <dyn MessageEncrypter>::invalid(),
            message_decrypter: <dyn MessageDecrypter>::invalid(),
            pending_encryption: None,
            pending_decryption: None,
            decryption_waker: None,
            write_seq_max: 0,
            write_seq: 0,
            read_seq: 0,
            has_decrypted: false,
            encrypt_state: DirectionState::Invalid,
            decrypt_state: DirectionState::Invalid,
            trial_decryption_len: None,
        }
    }

    pub(crate) fn set_decryption_waker(&mut self, waker: Option<&core::task::Waker>) {
        match waker {
            Some(waker) if !self.decryption_waker.as_ref().is_some_and(|old| old.will_wake(waker)) => {
                self.decryption_waker = Some(waker.clone());
            }
            None if self.pending_decryption.is_none() => self.decryption_waker = None,
            _ => {},
        }
    }
    pub(crate) fn decryption_pending(&self) -> bool { self.pending_decryption.is_some() }
    pub(crate) fn poll_decrypt_incoming<'a>(&mut self, mut encr: InboundOpaqueMessage<'a>)
        -> core::task::Poll<Result<Option<Decrypted<'a>>, Error>> {
        use core::task::{Context, Poll};
        // Trial decryption can discard several records within one deframer
        // iteration. Keep its established accounting until the handshake ends.
        if self.decryption_waker.is_none() || self.decrypt_state != DirectionState::Active
            || self.trial_decryption_len.is_some() {
            return Poll::Ready(self.decrypt_incoming(encr));
        }
        let waker = self.decryption_waker.as_ref().unwrap().clone();
        if self.pending_decryption.is_none() {
            self.pending_decryption = Some(self.message_decrypter.start_decrypt(
                InboundOpaqueMessage::new(encr.typ, encr.version, &mut encr.payload), self.read_seq));
        }
        let result = match self.pending_decryption.as_mut().unwrap().poll(&mut Context::from_waker(&waker)) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(result) => result,
        };
        self.pending_decryption = None;
        Poll::Ready(result.and_then(|plain| {
            if plain.payload.len() > encr.payload.len() { return Err(Error::DecryptError); }
            let want_close_before_decrypt = self.read_seq == SEQ_SOFT_LIMIT;
            encr.payload[..plain.payload.len()].copy_from_slice(&plain.payload);
            encr.payload.truncate(plain.payload.len());
            encr.typ = plain.typ;
            encr.version = plain.version;
            self.read_seq += 1;
            self.has_decrypted = true;
            Ok(Some(Decrypted { want_close_before_decrypt, plaintext: encr.into_plain_message() }))
        }))
    }

    /// Decrypt a TLS message.
    ///
    /// `encr` is a decoded message allegedly received from the peer.
    /// If it can be decrypted, its decryption is returned.  Otherwise,
    /// an error is returned.
    pub(crate) fn decrypt_incoming<'a>(
        &mut self,
        encr: InboundOpaqueMessage<'a>,
    ) -> Result<Option<Decrypted<'a>>, Error> {
        if self.decrypt_state != DirectionState::Active {
            return Ok(Some(Decrypted {
                want_close_before_decrypt: false,
                plaintext: encr.into_plain_message(),
            }));
        }

        // Set to `true` if the peer appears to getting close to encrypting
        // too many messages with this key.
        //
        // Perhaps if we send an alert well before their counter wraps, a
        // buggy peer won't make a terrible mistake here?
        //
        // Note that there's no reason to refuse to decrypt: the security
        // failure has already happened.
        let want_close_before_decrypt = self.read_seq == SEQ_SOFT_LIMIT;

        let encrypted_len = encr.payload.len();
        match self
            .message_decrypter
            .decrypt(encr, self.read_seq)
        {
            Ok(plaintext) => {
                self.read_seq += 1;
                if !self.has_decrypted {
                    self.has_decrypted = true;
                }
                Ok(Some(Decrypted {
                    want_close_before_decrypt,
                    plaintext,
                }))
            }
            Err(Error::DecryptError) if self.doing_trial_decryption(encrypted_len) => {
                trace!("Dropping undecryptable message after aborted early_data");
                Ok(None)
            }
            Err(err) => Err(err),
        }
    }

    /// Encrypt a TLS message.
    ///
    /// `plain` is a TLS message we'd like to send.  This function
    /// panics if the requisite keying material hasn't been established yet.
    pub(crate) fn encrypt_outgoing(
        &mut self,
        plain: OutboundPlainMessage<'_>,
    ) -> OutboundOpaqueMessage {
        debug_assert!(self.encrypt_state == DirectionState::Active);
        assert!(self.next_pre_encrypt_action() != PreEncryptAction::Refuse);
        assert!(self.pending_encryption.is_none(), "pending record must finish first");
        let seq = self.write_seq;
        self.write_seq += 1;
        self.message_encrypter
            .encrypt(plain, seq)
            .unwrap()
    }

    /// Reserve a sequence number once and retain the owned operation across
    /// polls. Failed/cancelled encryption never makes the nonce reusable.
    pub(crate) fn start_encrypt_outgoing(&mut self, plain: OutboundPlainMessage<'_>) -> Result<(), Error> {
        if self.pending_encryption.is_some() || self.encrypt_state != DirectionState::Active
            || self.next_pre_encrypt_action() == PreEncryptAction::Refuse {
            return Err(Error::EncryptError);
        }
        let seq=self.write_seq;
        self.write_seq+=1;
        self.pending_encryption=Some(self.message_encrypter.start_encrypt(plain,seq));
        Ok(())
    }

    pub(crate) fn poll_encrypt_outgoing(&mut self, cx:&mut core::task::Context<'_>)
        -> core::task::Poll<Result<OutboundOpaqueMessage,Error>> {
        use core::task::Poll;
        let Some(op)=self.pending_encryption.as_mut() else {return Poll::Ready(Err(Error::EncryptError));};
        match op.poll(cx) {
            Poll::Pending=>Poll::Pending,
            Poll::Ready(result)=>{self.pending_encryption=None;Poll::Ready(result)}
        }
    }

    pub(crate) fn encryption_pending(&self)->bool {self.pending_encryption.is_some()}

    /// Prepare to use the given `MessageEncrypter` for future message encryption.
    /// It is not used until you call `start_encrypting`.
    pub(crate) fn prepare_message_encrypter(
        &mut self,
        cipher: Box<dyn MessageEncrypter>,
        max_messages: u64,
    ) {
        assert!(self.pending_encryption.is_none(), "cannot replace a key with an outstanding record");
        self.message_encrypter = cipher;
        self.write_seq = 0;
        self.write_seq_max = min(SEQ_SOFT_LIMIT, max_messages);
        self.encrypt_state = DirectionState::Prepared;
    }

    /// Prepare to use the given `MessageDecrypter` for future message decryption.
    /// It is not used until you call `start_decrypting`.
    pub(crate) fn prepare_message_decrypter(&mut self, cipher: Box<dyn MessageDecrypter>) {
        assert!(self.pending_decryption.is_none(), "pending decrypt must finish before key replacement");
        self.message_decrypter = cipher;
        self.read_seq = 0;
        self.decrypt_state = DirectionState::Prepared;
    }

    /// Start using the `MessageEncrypter` previously provided to the previous
    /// call to `prepare_message_encrypter`.
    pub(crate) fn start_encrypting(&mut self) {
        debug_assert!(self.encrypt_state == DirectionState::Prepared);
        self.encrypt_state = DirectionState::Active;
    }

    /// Start using the `MessageDecrypter` previously provided to the previous
    /// call to `prepare_message_decrypter`.
    pub(crate) fn start_decrypting(&mut self) {
        debug_assert!(self.decrypt_state == DirectionState::Prepared);
        self.decrypt_state = DirectionState::Active;
    }

    /// Set and start using the given `MessageEncrypter` for future outgoing
    /// message encryption.
    pub(crate) fn set_message_encrypter(
        &mut self,
        cipher: Box<dyn MessageEncrypter>,
        max_messages: u64,
    ) {
        self.prepare_message_encrypter(cipher, max_messages);
        self.start_encrypting();
    }

    /// Set and start using the given `MessageDecrypter` for future incoming
    /// message decryption.
    pub(crate) fn set_message_decrypter(&mut self, cipher: Box<dyn MessageDecrypter>) {
        self.prepare_message_decrypter(cipher);
        self.start_decrypting();
        self.trial_decryption_len = None;
    }

    /// Set and start using the given `MessageDecrypter` for future incoming
    /// message decryption, and enable "trial decryption" mode for when TLS1.3
    /// 0-RTT is attempted but rejected by the server.
    pub(crate) fn set_message_decrypter_with_trial_decryption(
        &mut self,
        cipher: Box<dyn MessageDecrypter>,
        max_length: usize,
    ) {
        self.prepare_message_decrypter(cipher);
        self.start_decrypting();
        self.trial_decryption_len = Some(max_length);
    }

    pub(crate) fn finish_trial_decryption(&mut self) {
        self.trial_decryption_len = None;
    }

    pub(crate) fn next_pre_encrypt_action(&self) -> PreEncryptAction {
        self.pre_encrypt_action(0)
    }

    /// Return a remedial action when we are near to encrypting too many messages.
    ///
    /// `add` is added to the current sequence number.  `add` as `0` means
    /// "the next message processed by `encrypt_outgoing`"
    pub(crate) fn pre_encrypt_action(&self, add: u64) -> PreEncryptAction {
        match self.write_seq.saturating_add(add) {
            SEQ_HARD_LIMIT.. => PreEncryptAction::Refuse,
            v if v >= self.write_seq_max => PreEncryptAction::RefreshOrClose,
            _ => PreEncryptAction::Nothing,
        }
    }

    pub(crate) fn is_encrypting(&self) -> bool {
        self.encrypt_state == DirectionState::Active
    }

    /// Return true if we have ever decrypted a message. This is used in place
    /// of checking the read_seq since that will be reset on key updates.
    pub(crate) fn has_decrypted(&self) -> bool {
        self.has_decrypted
    }

    pub(crate) fn write_seq(&self) -> u64 {
        self.write_seq
    }

    pub(crate) fn read_seq(&self) -> u64 {
        self.read_seq
    }

    pub(crate) fn encrypted_len(&self, payload_len: usize) -> usize {
        self.message_encrypter
            .encrypted_payload_len(payload_len)
    }

    fn doing_trial_decryption(&mut self, requested: usize) -> bool {
        match self
            .trial_decryption_len
            .and_then(|value| value.checked_sub(requested))
        {
            Some(remaining) => {
                self.trial_decryption_len = Some(remaining);
                true
            }
            _ => false,
        }
    }
}

/// Result of decryption.
#[derive(Debug)]
pub(crate) struct Decrypted<'a> {
    /// Whether the peer appears to be getting close to encrypting too many messages with this key.
    pub(crate) want_close_before_decrypt: bool,
    /// The decrypted message.
    pub(crate) plaintext: InboundPlainMessage<'a>,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum PreEncryptAction {
    /// No action is needed before calling `encrypt_outgoing`
    Nothing,

    /// A `key_update` request should be sent ASAP.
    ///
    /// If that is not possible (for example, the connection is TLS1.2), a `close_notify`
    /// alert should be sent instead.
    RefreshOrClose,

    /// Do not call `encrypt_outgoing` further, it will panic rather than
    /// over-use the key.
    Refuse,
}

const SEQ_SOFT_LIMIT: u64 = 0xffff_ffff_ffff_0000u64;
const SEQ_HARD_LIMIT: u64 = 0xffff_ffff_ffff_fffeu64;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_record_reserves_nonce_once_and_never_returns_partial_output() {
        use core::task::{Context,Poll,Waker};
        use crate::crypto::cipher::{PendingEncryption,PrefixedPayload};
        use crate::{ContentType,ProtocolVersion};
        struct Cipher;
        struct Operation { first:bool, seq:u64 }
        impl PendingEncryption for Operation {
            fn poll(&mut self,cx:&mut Context<'_>)->Poll<Result<OutboundOpaqueMessage,Error>> {
                if self.first {self.first=false;cx.waker().wake_by_ref();return Poll::Pending;}
                Poll::Ready(Ok(OutboundOpaqueMessage::new(ContentType::ApplicationData,ProtocolVersion::TLSv1_2,PrefixedPayload::from(&self.seq.to_be_bytes()))))
            }
        }
        impl MessageEncrypter for Cipher {
            fn encrypt(&mut self,_:OutboundPlainMessage<'_>,_:u64)->Result<OutboundOpaqueMessage,Error>{panic!("must not take synchronous path")}
            fn start_encrypt(&mut self,_:OutboundPlainMessage<'_>,seq:u64)->Box<dyn PendingEncryption>{Box::new(Operation{first:true,seq})}
            fn encrypted_payload_len(&self,n:usize)->usize{n+16}
        }
        let msg=||OutboundPlainMessage{typ:ContentType::ApplicationData,version:ProtocolVersion::TLSv1_2,payload:(&b"record"[..]).into()};
        let mut layer=RecordLayer::new();layer.set_message_encrypter(Box::new(Cipher),100);
        let mut cx=Context::from_waker(Waker::noop());
        for seq in 0..3 {
            layer.start_encrypt_outgoing(msg()).unwrap();assert_eq!(layer.write_seq(),seq+1);
            assert!(layer.encryption_pending());assert!(layer.start_encrypt_outgoing(msg()).is_err());
            assert!(layer.poll_encrypt_outgoing(&mut cx).is_pending());assert_eq!(layer.write_seq(),seq+1);
            let Poll::Ready(Ok(out))=layer.poll_encrypt_outgoing(&mut cx) else{panic!("completion missing")};
            assert_eq!(out.payload.as_ref(),seq.to_be_bytes());assert!(!layer.encryption_pending());
            assert!(matches!(layer.poll_encrypt_outgoing(&mut cx),Poll::Ready(Err(Error::EncryptError))));
        }
    }

    #[test]
    fn pending_decryption_preserves_sequence_and_withholds_failed_output() {
        use crate::crypto::cipher::{OwnedPlaintext, PendingDecryption};
        use crate::{ContentType, ProtocolVersion};
        use core::task::{Context, Poll, Waker};
        struct Cipher(bool);
        struct Operation { pending: bool, fail: bool, seq: u64 }
        impl PendingDecryption for Operation {
            fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<OwnedPlaintext, Error>> {
                if self.pending { self.pending=false; cx.waker().wake_by_ref(); return Poll::Pending; }
                Poll::Ready(if self.fail { Err(Error::DecryptError) } else {
                    Ok(OwnedPlaintext {typ:ContentType::ApplicationData,version:ProtocolVersion::TLSv1_3,payload:self.seq.to_be_bytes().to_vec()})
                })
            }
        }
        impl MessageDecrypter for Cipher {
            fn decrypt<'a>(&mut self,_:InboundOpaqueMessage<'a>,_:u64)->Result<InboundPlainMessage<'a>,Error> {panic!("synchronous decrypt")}
            fn start_decrypt(&mut self,_:InboundOpaqueMessage<'_>,seq:u64)->Box<dyn PendingDecryption> {
                Box::new(Operation {pending:true,fail:self.0,seq})
            }
        }
        for fail in [false,true] {
            let mut layer=RecordLayer::new();
            layer.set_message_decrypter(Box::new(Cipher(fail)));
            layer.set_decryption_waker(Some(Waker::noop()));
            let mut input=[0xa5;32];
            assert!(layer.poll_decrypt_incoming(InboundOpaqueMessage::new(ContentType::ApplicationData,ProtocolVersion::TLSv1_2,&mut input)).is_pending());
            assert_eq!(input,[0xa5;32]);
            assert_eq!(layer.read_seq,0);
            assert!(!layer.has_decrypted());
            // Disabling async reception cannot reroute a record already admitted.
            layer.set_decryption_waker(None);
            let result=layer.poll_decrypt_incoming(InboundOpaqueMessage::new(ContentType::ApplicationData,ProtocolVersion::TLSv1_2,&mut input));
            if fail {
                assert!(matches!(result,Poll::Ready(Err(Error::DecryptError))));
                assert_eq!(input,[0xa5;32]);
                assert_eq!(layer.read_seq,0);
                assert!(!layer.has_decrypted());
            } else {
                let Poll::Ready(Ok(Some(result)))=result else {panic!("missing plaintext")};
                assert_eq!(result.plaintext.payload,&[0;8]);
                assert_eq!(layer.read_seq,1);
                assert!(layer.has_decrypted());
            }
            assert!(!layer.decryption_pending());
        }
    }

    #[test]
    fn pre_encrypt_action_checks_limits() {
        let action = |write_seq_max, write_seq, add| {
            let mut record_layer = RecordLayer::new();
            record_layer.write_seq_max = write_seq_max;
            record_layer.write_seq = write_seq;
            record_layer.pre_encrypt_action(add)
        };

        assert_eq!(action(10, 8, 1), PreEncryptAction::Nothing);
        assert_eq!(action(10, 8, 2), PreEncryptAction::RefreshOrClose);
        assert_eq!(action(10, 11, 0), PreEncryptAction::RefreshOrClose);
        assert_eq!(
            action(SEQ_SOFT_LIMIT, SEQ_HARD_LIMIT - 1, 0),
            PreEncryptAction::RefreshOrClose
        );
        assert_eq!(
            action(SEQ_SOFT_LIMIT, SEQ_HARD_LIMIT - 1, 1),
            PreEncryptAction::Refuse
        );
    }

    #[test]
    fn test_has_decrypted() {
        use crate::{ContentType, ProtocolVersion};

        struct PassThroughDecrypter;
        impl MessageDecrypter for PassThroughDecrypter {
            fn decrypt<'a>(
                &mut self,
                m: InboundOpaqueMessage<'a>,
                _: u64,
            ) -> Result<InboundPlainMessage<'a>, Error> {
                Ok(m.into_plain_message())
            }
        }

        // A record layer starts out invalid, having never decrypted.
        let mut record_layer = RecordLayer::new();
        assert!(matches!(
            record_layer.decrypt_state,
            DirectionState::Invalid
        ));
        assert_eq!(record_layer.read_seq, 0);
        assert!(!record_layer.has_decrypted());

        // Preparing the record layer should update the decrypt state, but shouldn't affect whether it
        // has decrypted.
        record_layer.prepare_message_decrypter(Box::new(PassThroughDecrypter));
        assert!(matches!(
            record_layer.decrypt_state,
            DirectionState::Prepared
        ));
        assert_eq!(record_layer.read_seq, 0);
        assert!(!record_layer.has_decrypted());

        // Starting decryption should update the decrypt state, but not affect whether it has decrypted.
        record_layer.start_decrypting();
        assert!(matches!(record_layer.decrypt_state, DirectionState::Active));
        assert_eq!(record_layer.read_seq, 0);
        assert!(!record_layer.has_decrypted());

        // Decrypting a message should update the read_seq and track that we have now performed
        // a decryption.
        record_layer
            .decrypt_incoming(InboundOpaqueMessage::new(
                ContentType::Handshake,
                ProtocolVersion::TLSv1_2,
                &mut [0xC0, 0xFF, 0xEE],
            ))
            .unwrap();
        assert!(matches!(record_layer.decrypt_state, DirectionState::Active));
        assert_eq!(record_layer.read_seq, 1);
        assert!(record_layer.has_decrypted());

        // Resetting the record layer message decrypter (as if a key update occurred) should reset
        // the read_seq number, but not our knowledge of whether we have decrypted previously.
        record_layer.set_message_decrypter(Box::new(PassThroughDecrypter));
        assert!(matches!(record_layer.decrypt_state, DirectionState::Active));
        assert_eq!(record_layer.read_seq, 0);
        assert!(record_layer.has_decrypted());
    }
}
