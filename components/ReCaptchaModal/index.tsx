import { PortkeyStyleProvider } from '@portkey/did-ui-react';
import ReCaptchaModalCom from './index.component';

export default function ReCaptchaModal() {
  return (
    <PortkeyStyleProvider>
      <ReCaptchaModalCom />
    </PortkeyStyleProvider>
  );
}
