import { useEffect, useCallback, useState, useRef } from 'react';
import { SET_RECAPTCHA_MODAL } from '../../constants/events';
import { setReCaptchaModal } from '../../utils/reCaptcha';
import { useUpdateEffect } from 'react-use';
import { eventBus } from '@/utils';
import { BaseReCaptchaHandler, CommonModal, setLoading } from '@portkey/did-ui-react';

const ReCaptchaIframe = `${'https://openlogin-testnet.portkey.finance'}/recaptcha`;

export default function ReCaptchaModal() {
  const [modalInfo, setModalInfo] = useState<
    {
      open?: boolean;
    } & BaseReCaptchaHandler
  >();

  const setHandler = useCallback((open?: boolean, handlers?: BaseReCaptchaHandler) => {
    if (open) setModalLoading(true);
    setModalInfo({
      open,
      ...handlers,
    });
  }, []);

  const errorRef = useRef<any>();

  useEffect(() => {
    eventBus.addListener(SET_RECAPTCHA_MODAL, setHandler);
    return () => {
      eventBus.removeListener(SET_RECAPTCHA_MODAL, setHandler);
    };
  }, [setHandler]);

  const closeModal = useCallback(() => {
    setReCaptchaModal(false);
  }, []);

  const onCancel = useCallback(() => {
    if (!errorRef.current) modalInfo?.onCancel?.();
    closeModal();
  }, [closeModal, modalInfo]);

  const [isLoading, setModalLoading] = useState(false);

  const eventHandler = useCallback(
    (event: MessageEvent<any>) => {
      if (event.data.target === '@portkey/ui-did-react:ReCaptcha') {
        switch (event.data.type) {
          case 'PortkeyReCaptchaOnSuccess':
            modalInfo?.onSuccess?.(event.data.data);
            closeModal();
            break;
        }
      }
    },
    [closeModal, modalInfo],
  );

  const connect = useCallback(() => {
    window.addEventListener('message', eventHandler);
  }, [eventHandler]);

  useUpdateEffect(() => {
    if (modalInfo?.open) {
      connect();
      setLoading(true);
    } else {
      setModalLoading(true);
      window.removeEventListener('message', eventHandler);
    }
  }, [modalInfo?.open]);

  const timeRef = useRef<NodeJS.Timeout | null>();

  const iframeLoad = useCallback(() => {
    setModalLoading(false);
    if (timeRef.current) clearTimeout(timeRef.current);
    timeRef.current = setTimeout(() => {
      timeRef.current && clearTimeout(timeRef.current);
      timeRef.current = null;
      setLoading(false);
    }, 1000);
  }, []);

  return (
    <CommonModal
      type="modal"
      className={'reCaptcha-modal-container'}
      open={modalInfo?.open}
      width={600}
      onClose={onCancel}>
      <div className="reCaptcha-modal-inner">
        <iframe
          onLoad={iframeLoad}
          style={{ width: isLoading ? 0 : '100%', border: '0' }}
          src={`${ReCaptchaIframe}`}></iframe>
      </div>
    </CommonModal>
  );
}
