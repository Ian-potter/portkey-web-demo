import { useCallback } from 'react';
import { OperationTypeEnum } from '@portkey/services';
import { ReCaptchaResponseType, handleErrorMessage } from '@portkey/did-ui-react';
import { did } from '@portkey/did';
import { setReCaptchaModal } from '@/utils/reCaptcha';

export default function useReCaptchaModal() {
  return useCallback(
    async (
      open?: boolean,
      operationType: OperationTypeEnum = OperationTypeEnum.register,
    ): Promise<{ type: ReCaptchaResponseType; message?: any }> => {
      if (open) {
        let needGoogleRecaptcha = true;
        // When the operationType is register, the google recaptcha is required.
        if (operationType !== OperationTypeEnum.register) {
          needGoogleRecaptcha = await did.services.checkGoogleRecaptcha({
            operationType,
          });
        }
        if (!needGoogleRecaptcha) return { type: 'success', message: 'not use' };
      }

      try {
        const info = await setReCaptchaModal(open);
        if (info.type === 'success') return info;
        throw info;
      } catch (e: any) {
        if (e.type === 'cancel') throw handleErrorMessage(e, 'User Cancel');
        if (e.type === 'error') throw handleErrorMessage(e, 'ReCaptcha error');
        if (e.type === 'expire') throw handleErrorMessage(e, 'ReCaptcha expire');
        throw e;
      }
    },
    [],
  );
}
