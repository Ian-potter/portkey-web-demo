'use client';
import { CAInfo, did } from '@portkey/did';
import { useCallback, useMemo, useRef, useState } from 'react';
import {
  forgeWeb,
  randomId,
  parseAppleIdentityToken,
  getGoogleUserInfo,
  parseTelegramToken,
  aelf,
} from '@portkey/utils';
import qs from 'query-string';
import { socialLoginList } from '@/constants/login';
import { openloginSignal, CrossTabPushMessageType } from '@portkey/socket';
import { Actions, useExampleState } from '@/hooks/useExampleState';
import {
  BaseGuardianItem,
  CommonBaseModal,
  ConfigProvider,
  ErrorInfo,
  GuardianApproval,
  IGuardiansApproved,
  PortkeyProvider,
  handleErrorMessage,
  setLoading,
  singleMessage,
} from '@portkey/did-ui-react';
import '@portkey/did-ui-react/dist/assets/index.css';
import { ChainId } from '@portkey/types';
import { BaseAsyncStorage } from '@/utils/asyncStorage';
import { verification } from '@/utils/verification';
import useReCaptchaModal from '@/hooks/useReCaptchaModal';
import ReCaptchaModal from '@/components/ReCaptchaModal';
import { useLoginWallet } from '@/hooks/useLoginWallet';
import {
  AccountType,
  IWalletBalanceCheckResponse,
  OperationTypeEnum,
  IPaymentSecurityListResponse,
  GuardiansApproved,
  AccountTypeEnum,
} from '@portkey/services';
import clsx from 'clsx';
import { getGuardianList } from '@/utils/getGuardians';
import { Button, Card, Col, Divider, Input, Row, Space } from 'antd';
import ReactJson from 'react-json-view';
import 'antd/dist/antd.variable.min.css';
import { IPortkeyContract, getContractBasic } from '@portkey/contracts';
import { getChain } from '@/utils/getChainInfo';
import { TRANSFER_PARAMS, INIT_CONTRACT_PARAMS, DID_CONFIG, APPROVE_PARAMS } from '@/constants/params';
import BigNumber from 'bignumber.js';
import Header from '@/components/Header';
import { divDecimals, timesDecimals } from '@/utils/converter';
import { ZERO } from '@/constants/misc';
import { DEFAULT_DECIMAL } from '@/constants';

did.setConfig({
  ...DID_CONFIG,
  storageMethod: new BaseAsyncStorage(),
});

const WALLET_KEY = 'portkey_sdk_did_wallet';

export default function Home() {
  const [inputVal, setInputVal] = useState('');

  const invokeTimerRef = useRef<number>();

  const [state, dispatch] = useExampleState();

  const getResultByInvoke = useCallback((clientId: string, methodName: string) => {
    return new Promise(async resolve => {
      if (invokeTimerRef.current) clearInterval(invokeTimerRef.current);
      invokeTimerRef.current = Number(
        setInterval(async () => {
          const result = await openloginSignal.GetTabDataAsync({
            requestId: clientId,
            methodName: methodName as any,
          });
          if (result?.data) {
            clearInterval(invokeTimerRef.current);
            resolve(result.data);
          }
        }, 1000),
      );
    });
  }, []);

  const onSocialLogin = useCallback(
    async (type: (typeof socialLoginList)[number]) => {
      const cryptoManager = new forgeWeb.ForgeCryptoManager();
      const keyPair = await cryptoManager.generateKeyPair();
      const loginId = randomId();

      // Get login url

      const queryParams = {
        publicKey: keyPair.publicKey,
        serviceURI: DID_CONFIG.requestDefaults.baseURL,
        actionType: 'login',
        loginProvider: type,
        loginId,
        network: 'online',
      };

      const loginUrl = `https://openlogin-testnet.portkey.finance/social-start?${qs.stringify({
        b64Params: Buffer.from(JSON.stringify(queryParams)).toString('base64'),
      })}`;

      // open social auth page
      const windowOpener = window.open(loginUrl, '_blank');

      // connect socket

      await openloginSignal.doOpen({
        url: `${DID_CONFIG.requestDefaults.baseURL}/communication`,
        clientId: loginId,
      });

      const result: any = await Promise.race([
        getResultByInvoke(loginId, CrossTabPushMessageType.onAuthStatusChanged),
        new Promise(resolve =>
          openloginSignal.onAuthStatusChanged({ requestId: loginId }, (result: any) => {
            const message = result;
            resolve(message);
          }),
        ),
      ]);

      console.log(result, 'result===');

      const decrypted = await cryptoManager.decryptLong(keyPair.privateKey, result);
      console.log(decrypted, 'decrypted==');
      let tokenResult = JSON.parse(decrypted);
      console.log(tokenResult, 'decrypted==');

      windowOpener?.close();

      if (tokenResult?.code) throw tokenResult.message;

      const { token } = tokenResult;
      let identifier;
      if (type === 'Apple') {
        identifier = parseAppleIdentityToken(token)?.userId;
      } else if (type === 'Google') {
        identifier = (await getGoogleUserInfo(token)).id;
      } else if (type === 'Telegram') {
        identifier = parseTelegramToken(token)?.userId;
      }

      if (!identifier) return;
      return { accountType: type, token, identifier };
    },
    [getResultByInvoke],
  );

  const onCheckEmail = useCallback(() => {
    const EmailReg = /^\w+([-+.]\w+)*@\w+([-.]\w+)*\.\w+([-.]\w+)*$/;
    if (!inputVal || !EmailReg.test(inputVal)) {
      singleMessage.error('Incorrect email format');
      setInputVal('');
      return;
    }
    dispatch({
      type: Actions.setIdentifierInfo,
      payload: { identifierInfo: { accountType: 'Email', identifier: inputVal } },
    });
  }, [dispatch, inputVal]);

  const onStep1Finish = useCallback(
    (isLoginGuardian: boolean, originChainId: ChainId) => {
      const { identifier, accountType, token } = state.identifierInfo ?? {};
      if (!identifier) return singleMessage.error('No identifier');
      if (!accountType) return singleMessage.error('No accountType');
      dispatch({
        type: Actions.setState,
        payload: {
          step1FinishStore: {
            chainId: originChainId,
            isLoginGuardian,
            identifier: identifier.replaceAll(/\s+/g, ''),
            accountType,
            authenticationInfo: {
              authToken: token,
            },
          },
        },
      });
    },
    [dispatch, state.identifierInfo],
  );

  const onValidateIdentifier = useCallback(async () => {
    const { identifier, accountType, token } = state.identifierInfo ?? {};
    if (!identifier) return singleMessage.error('No identifier');
    if (!accountType) return singleMessage.error('No accountType');
    // Get the identifier information,
    // When the status code is 403 and the return value code is 3002, it means the user does not exist
    try {
      setLoading(true);
      const { originChainId } = await did.services.getRegisterInfo({
        loginGuardianIdentifier: identifier,
      });
      const payload = await did.getHolderInfo({
        loginGuardianIdentifier: identifier,
        chainId: originChainId,
      });
      setLoading(false);

      if (payload?.guardianList?.guardians?.length > 0) {
        onStep1Finish(true, originChainId);

        singleMessage.success(
          `The current account has been registered, the registration chain is ${originChainId}, please log in next`,
        );

        console.log('Identifier is login guardian identifier, which can be used for login');
        dispatch({
          type: Actions.changeIdentifierInfo,
          payload: { identifierInfo: { isLoginGuardian: true } },
        });
      }
    } catch (errorInfo: any) {
      setLoading(false);

      console.log(errorInfo);
      if (errorInfo.error.code === '3002') {
        dispatch({
          type: Actions.changeIdentifierInfo,
          payload: { identifierInfo: { isLoginGuardian: false } },
        });
        onStep1Finish(false, 'tDVW');

        singleMessage.success('The current account is not registered, please register in the next step!');

        console.log('The identifier has not been registered yet, prompt the user to register.');
        return; //
      }
      singleMessage.error(handleErrorMessage(errorInfo, 'Something error'));
    }
  }, [dispatch, onStep1Finish, state.identifierInfo]);

  const [inputChainId, setInputChainId] = useState<string>('tDVW');
  const [targetChainId, setTargetChainId] = useState<ChainId>('tDVW');

  const onCheckChainId = useCallback(() => {
    if (inputChainId !== 'AELF' && inputChainId !== 'tDVW')
      return singleMessage.error('Currently it is a non-delete environment, only AELF/tDVW is supported');
    if (!state.identifierInfo?.identifier)
      return singleMessage.error('Currently it is a non-delete environment, only AELF/tDVW is supported');

    onStep1Finish(false, inputChainId);
  }, [inputChainId, onStep1Finish, state.identifierInfo?.identifier]);

  const getRecommendationVerifier = useCallback(async () => {
    onCheckChainId();
    if (!inputChainId) return singleMessage.error('Please setOriginChainId');
    setLoading(true);
    try {
      const verifier = await did.services.getRecommendationVerifier({
        chainId: inputChainId as ChainId,
      });
      console.log('RecommendationVerifier:', verifier);
      dispatch({
        type: Actions.changeVerificationStore,
        payload: { verificationStore: { [state.step1FinishStore?.identifier || 'recommend']: verifier } },
      });
    } finally {
      setLoading(false);
    }
  }, [dispatch, inputChainId, onCheckChainId, state.step1FinishStore?.identifier]);

  const onMessage = useCallback(
    (
      event: MessageEvent<{
        data: string;
        target: string; //"@portkey/ui-did-react:ReCaptcha";
        type: string; // "PortkeyReCaptchaOnSuccess";
      }>,
    ) => {
      if (event.data.target === '@portkey/ui-did-react:ReCaptcha' && event.data.type === 'PortkeyReCaptchaOnSuccess') {
        const reCaptchaToken = event.data.data;
        console.log('reCaptchaToken:', reCaptchaToken);
        dispatch({ type: Actions.setState, payload: {} });

        singleMessage.success(reCaptchaToken);
        setShowRecaptcha(false);
        window.removeEventListener('message', onMessage);
      }
    },
    [dispatch],
  );

  const onCreateManager = useCallback(() => {
    did.create();
    dispatch({ type: Actions.setState, payload: { manager: did.didWallet.managementAccount?.wallet } });
  }, [dispatch]);

  const [showRecaptcha, setShowRecaptcha] = useState(false);

  const onGoogleRecaptcha = useCallback(() => {
    setShowRecaptcha(true);
    window.addEventListener('message', onMessage);
  }, [onMessage]);

  const reCaptchaHandler = useReCaptchaModal();

  const onSendVerificationCode = useCallback(
    async ({ identifier, operationType }: { operationType: OperationTypeEnum; identifier: string }) => {
      if (!state.verificationStore) return singleMessage.error('Please get verification!');
      if (!state.step1FinishStore) return singleMessage.error('Please finish setp1!');
      const verifier = state.verificationStore[identifier];
      if (!verifier) return singleMessage.error('Please set verifier!');
      const chainId = state.step1FinishStore.chainId;
      if (!chainId) return singleMessage.error('Please set chainId!');

      try {
        console.log('sendVerificationCode', 'item==sendVerificationCode');

        const result = await verification.sendVerificationCode(
          {
            params: {
              type: state.step1FinishStore.accountType,
              guardianIdentifier: state.step1FinishStore.identifier,
              verifierId: verifier.id,
              chainId: state.step1FinishStore.chainId,
              operationType,
            },
          },
          reCaptchaHandler,
        );
        if (!result.verifierSessionId)
          return console.warn('The request was rejected, please check whether the parameters are correct');

        dispatch({
          type: Actions.changeVerificationStore,
          payload: {
            verificationStore: { [identifier]: { ...verifier, verifierSessionId: result.verifierSessionId } },
          },
        });
        singleMessage.success(`Please check your email (${state.step1FinishStore.identifier})`);
      } catch (error) {
        singleMessage.error(handleErrorMessage(error, 'sendVerificationCode error'));
      }
    },
    [state.verificationStore, state.step1FinishStore, reCaptchaHandler, dispatch],
  );

  const [verifierCode, setVerifierCode] = useState<string>('');

  const onVerifyVerificationCode = useCallback(
    async ({
      identifier,
      operationType,
      operationDetails,
    }: {
      operationType: OperationTypeEnum;
      operationDetails: string;
      identifier: string;
    }) => {
      try {
        if (!state.step1FinishStore?.identifier) throw Error('Please get identifier');
        if (!state.verificationStore) throw Error(' Please set verificationStore');
        const verifierInfo = state.verificationStore[identifier];

        setLoading(true);
        if (!verifierInfo.verifierSessionId) throw Error(`VerifierSessionId is invalid`);

        const req = await verification.checkVerificationCode({
          verifierSessionId: verifierInfo.verifierSessionId,
          verificationCode: verifierCode,
          guardianIdentifier: identifier,
          verifierId: verifierInfo.id,
          chainId: state.step1FinishStore.chainId,
          operationType,
          operationDetails,
        });
        setLoading(false);

        if (!req || !req.verificationDoc) throw Error('The account has been restricted!');
        return req;
      } catch (error) {
        singleMessage.error(handleErrorMessage(error, 'verify code error'));
      }
    },
    [state.step1FinishStore, state.verificationStore, verifierCode],
  );

  const onVerifySocial = useCallback(
    async ({
      accountType,
      ...params
    }: {
      accountType: AccountType;
      operationType: OperationTypeEnum;
      verifierId: string;
      chainId: ChainId;
      targetChainId?: ChainId;
      accessToken: string;
      operationDetails: string;
    }) => {
      switch (accountType) {
        case 'Apple':
          return did.services.communityRecovery.verifyAppleToken({ ...params, identityToken: params.accessToken });
        case 'Google':
          return did.services.communityRecovery.verifyGoogleToken(params);
        case 'Telegram':
          return did.services.communityRecovery.verifyTelegramToken(params);
      }
    },
    [],
  );

  const onRegisterVerify = useCallback(async () => {
    if (!state.step1FinishStore) return;
    if (!state.verificationStore) return;

    const { accountType, identifier, chainId, authenticationInfo } = state.step1FinishStore;
    const { id } = state.verificationStore[identifier];
    const result = await onVerifySocial({
      accountType,
      operationType: OperationTypeEnum.register,
      verifierId: id,
      chainId: chainId,
      accessToken: authenticationInfo?.authToken || '',
      operationDetails: JSON.stringify({ manager: did.didWallet.managementAccount?.address }),
    });
    if (!result) return;
    singleMessage.success('Verify success');

    dispatch({
      type: Actions.setState,
      payload: {
        step2FinishStore: [
          {
            type: state.step1FinishStore.accountType,
            identifier: identifier,
            verifierId: id,
            verificationDoc: result.verificationDoc,
            signature: result.signature,
          },
        ],
      },
    });
  }, [dispatch, onVerifySocial, state.step1FinishStore, state.verificationStore]);

  const [pin, setPin] = useState<string>('111111');

  const onCheckPin = useCallback(() => {
    const PIN_REG = /^[a-zA-Z\d! ~@#_^*%/.+:;=\\|,'~{}\[\]]{6,16}$/;
    if (!pin || !PIN_REG.test(pin)) {
      singleMessage.error('Incorrect pin format');
      setPin('');
      return;
    }
  }, [pin]);

  const createPortkeyWallet = useLoginWallet();
  const [aaInfo, setAaInfo] = useState<CAInfo>();

  const onCreateWallet = useCallback(
    async (type: 'register' | 'recovery') => {
      if (!state.step1FinishStore) return singleMessage.error('Please set step1FinishStore');
      if (!state.step2FinishStore) return singleMessage.error('Please set step2FinishStore');

      await createPortkeyWallet({
        pin,
        type,
        chainId: state.step1FinishStore.chainId,
        accountType: state.step1FinishStore.accountType,
        guardianIdentifier: state.step1FinishStore.identifier,
        guardianApprovedList: state.step2FinishStore,
      });
      singleMessage.success('success');
      await did.save(pin, WALLET_KEY);
      localStorage.setItem('originChainId', state.step1FinishStore.chainId);
      did.didWallet.aaInfo.accountInfo && setAaInfo(did.didWallet.aaInfo.accountInfo);
    },
    [createPortkeyWallet, pin, state.step1FinishStore, state.step2FinishStore],
  );

  const isSignUp = useMemo(
    () => typeof state.step1FinishStore?.isLoginGuardian !== 'undefined' && !state.step1FinishStore?.isLoginGuardian,
    [state.step1FinishStore?.isLoginGuardian],
  );

  const [guardianList, setGuardianList] = useState<BaseGuardianItem[]>();

  const [openInfo, setOpenType] = useState<
    { operationType: OperationTypeEnum; operationDetails: string } | undefined
  >();

  console.log(openInfo, 'openInfo====');

  const onGetGuardianList = useCallback(
    async ({ identifier, chainId, caHash }: { identifier?: string; chainId: ChainId; caHash?: string }) => {
      const list = await getGuardianList({
        identifier,
        chainId,
        caHash,
      });
      singleMessage.success('Get guardian list success!');
      setGuardianList(list);
    },
    [],
  );

  const onApprovalError = useCallback(
    ({ error, errorFields }: ErrorInfo<any>) => singleMessage.error(handleErrorMessage(error, errorFields)),
    [],
  );

  const onGuardianApprove = useCallback(() => {
    // why set config?
    // @portkey/did-ui-react is used here, which needs to be configured separately.
    // If you do not use @portkey/did-ui-react, you can use the above method to obtain a token for the third-party authorization.

    ConfigProvider.setGlobalConfig({
      serviceUrl: DID_CONFIG.requestDefaults.baseURL,
    });
    setOpenType({
      operationType: OperationTypeEnum.communityRecovery,
      operationDetails: JSON.stringify({
        manager: did.didWallet.managementAccount?.address,
      }),
    });
  }, []);

  const portkeyContractRef = useRef<IPortkeyContract>();
  const tokenContractRef = useRef<IPortkeyContract>();

  const onInitContract = useCallback(async () => {
    const privateKey = did.didWallet.managementAccount?.privateKey;
    if (!privateKey) return singleMessage.error('Please login or unlock!');
    if (portkeyContractRef.current || tokenContractRef.current) return;
    try {
      setLoading(true);

      const chainInfo = await getChain('tDVW');

      portkeyContractRef.current = await getContractBasic({
        contractAddress: chainInfo.caContractAddress,
        account: aelf.getWallet(privateKey),
        rpcUrl: chainInfo.endPoint,
      });

      tokenContractRef.current = await getContractBasic({
        contractAddress: chainInfo.defaultToken.address,
        account: aelf.getWallet(privateKey),
        rpcUrl: chainInfo.endPoint,
      });
      singleMessage.success('success');
    } catch (error) {
      singleMessage.error(handleErrorMessage(error, 'InitContract error'));
    } finally {
      setLoading(false);
    }
  }, []);

  const [transferParams, setTransferParams] = useState(TRANSFER_PARAMS);

  const [approveParams, setApproveParams] = useState(APPROVE_PARAMS);

  const onTransfer = useCallback(async () => {
    if (!portkeyContractRef.current) return singleMessage.error('Please Init contract');
    if (!did.didWallet.aaInfo.accountInfo?.caHash) return singleMessage.error('Please login or unlock!');
    try {
      setLoading(true);

      const result = await portkeyContractRef.current.callSendMethod('ManagerTransfer', '', {
        ...transferParams,
        caHash: did.didWallet.aaInfo.accountInfo?.caHash,
      });
      if (result.error) return singleMessage.error(handleErrorMessage(result.error, 'ManagerTransfer error'));
      return singleMessage.success(`transactionId: ${result.transactionId}`);
    } catch (error) {
      singleMessage.error(handleErrorMessage(error, 'ManagerTransfer error'));
    } finally {
      setLoading(false);
    }
  }, [transferParams]);

  const onManagerApproveHandler = useCallback(async () => {
    if (!portkeyContractRef.current) return singleMessage.error('Please Init contract');
    if (!did.didWallet.aaInfo.accountInfo?.caHash) return singleMessage.error('Please login or unlock!');
    try {
      setLoading(true, 'Get GuardianList...');
      const originChainId = (localStorage.getItem('originChainId') as ChainId) || 'tDVW';

      await onGetGuardianList({ caHash: did.didWallet.aaInfo.accountInfo.caHash, chainId: originChainId });

      setOpenType({
        operationDetails: JSON.stringify({
          spender: approveParams.spender,
          symbol: approveParams.symbol,
          amount: approveParams.amount,
        }),
        operationType: OperationTypeEnum.managerApprove,
      });
    } catch (error) {
      singleMessage.error(handleErrorMessage(error, 'ManagerApprove error'));
    } finally {
      setLoading(false);
    }
  }, [approveParams.amount, approveParams.spender, approveParams.symbol, onGetGuardianList]);

  const onManagerApprove = useCallback(
    async (approvalInfo: IGuardiansApproved[]) => {
      if (!portkeyContractRef.current) return singleMessage.error('Please Init contract');
      if (!did.didWallet.aaInfo.accountInfo?.caHash) return singleMessage.error('Please login or unlock!');
      try {
        setLoading(true, 'ManagerApprove...');
        const params = {
          caHash: did.didWallet.aaInfo.accountInfo?.caHash,
          spender: approveParams.spender,
          symbol: approveParams.symbol,
          amount: approveParams.amount,
          guardiansApproved: approvalInfo,
        };

        console.log('ManagerApprove params:', params);

        const result = await portkeyContractRef.current.callSendMethod('ManagerApprove', '', params);

        if (result.error) throw result.error;
        singleMessage.success(`transactionId: ${result.transactionId}`);
        setLoading(true, 'GetAllowance...');

        const allowanceRes = await tokenContractRef.current?.callViewMethod('GetAllowance', {
          symbol: approveParams.symbol,
          owner: did.didWallet.aaInfo.accountInfo.caAddress,
          spender: approveParams.spender,
        });
        if (allowanceRes?.error || !allowanceRes) throw allowanceRes?.error;
        const allowance = divDecimals(allowanceRes.data.allowance ?? allowanceRes.data.amount ?? 0, 8);
        singleMessage.success(`allowance: ${allowance}`);
      } catch (error) {
        console.log('ManagerTransfer error:', error);
        singleMessage.error(handleErrorMessage(error, 'ManagerTransfer error'));
      } finally {
        setLoading(false);
      }
    },
    [approveParams.amount, approveParams.spender, approveParams.symbol],
  );

  const onGetBalance = useCallback(async () => {
    try {
      setLoading(true);

      if (!tokenContractRef.current) return singleMessage.error('Please Init contract');
      const result = await tokenContractRef.current.callViewMethod('GetBalance', {
        symbol: 'ELF',
        owner: did.didWallet.aaInfo.accountInfo?.caAddress,
      });
      if (result.error) return singleMessage.error(handleErrorMessage(result.error, 'GetBalance error'));
      return singleMessage.success(`balance: ${new BigNumber(result.data.balance).div(1e8).toFixed()} ELF`);
    } catch (error) {
      singleMessage.error(handleErrorMessage(error, 'ManagerTransfer error'));
    } finally {
      setLoading(false);
    }
  }, []);

  const checkLogin = useCallback(() => {
    if (!did.didWallet.aaInfo.accountInfo?.caHash || !did.didWallet.managementAccount?.privateKey) {
      singleMessage.error('Please login or unlock!');
      return false;
    }
    return true;
  }, []);

  const onCheckWalletSecurity = useCallback(async () => {
    if (!checkLogin()) return;
    try {
      setLoading(true);

      const result: IWalletBalanceCheckResponse = await did.services.security.getWalletBalanceCheck({
        caHash: did.didWallet.aaInfo.accountInfo!.caHash,
        checkTransferSafeChainId: targetChainId,
      });
      if (result.isTransferSafe) return singleMessage.success('The transfer is safe, you can transfer');
      const originChainId = localStorage.getItem('originChainId');

      if (originChainId === targetChainId && result.isOriginChainSafe)
        return singleMessage.success('The transfer is safe, you can transfer');

      if (result.isSynchronizing && result.isOriginChainSafe) return singleMessage.success('Guaridan is syncing...');

      return singleMessage.success(
        'You have too few guardians to protect your wallet. Please add at least one more guardian before proceeding.',
      );
    } catch (error) {
      singleMessage.error(handleErrorMessage(error, 'ManagerTransfer error'));
    } finally {
      setLoading(false);
    }
  }, [checkLogin, targetChainId]);

  const [paymentSecurityList, setPaymentSecurityList] = useState<IPaymentSecurityListResponse['data']>();

  const onGetPaymentSecurity = useCallback(async () => {
    if (!checkLogin()) return;

    try {
      setLoading(true);

      const res: IPaymentSecurityListResponse = await did.services.security.getPaymentSecurityList({
        caHash: did.didWallet.aaInfo.accountInfo!.caHash,
        skipCount: 0,
        maxResultCount: 50,
      });
      setPaymentSecurityList(res.data);
      console.log(res, 'res==getPaymentSecurityList');
    } catch (error) {
      singleMessage.error(handleErrorMessage(error, 'onGetPaymentSecurity error'));
    } finally {
      setLoading(false);
    }
  }, [checkLogin]);

  const [paymentCount, setPaymentCount] = useState<string>('1');
  const [paymentLimit, setPaymentLimit] = useState<any>();

  const onCheckPaymentSecurity = useCallback(async () => {
    if (!checkLogin()) return;

    if (!portkeyContractRef.current) return singleMessage.error('Please Init contract');
    try {
      setLoading(true);
      const [limitReq, defaultLimitReq] = await Promise.all([
        portkeyContractRef.current.callViewMethod('GetTransferLimit', {
          caHash: did.didWallet.aaInfo.accountInfo!.caHash,
          symbol: 'ELF',
        }),
        portkeyContractRef.current.callViewMethod('GetDefaultTokenTransferLimit', {
          caHash: did.didWallet.aaInfo.accountInfo!.caHash,
          symbol: 'ELF',
        }),
      ]);
      console.log(limitReq, defaultLimitReq);
      const bigAmount = timesDecimals(paymentCount, DEFAULT_DECIMAL);
      let dailyBalance, singleBalance, dailyLimit, defaultDailyLimit, defaultSingleLimit;

      if (!limitReq?.error) {
        const { singleLimit, dailyLimit: contractDailyLimit, dailyTransferredAmount } = limitReq.data || {};
        dailyLimit = ZERO.plus(contractDailyLimit);
        dailyBalance = dailyLimit.minus(dailyTransferredAmount);
        singleBalance = ZERO.plus(singleLimit);
      } else if (!defaultLimitReq?.error) {
        const { defaultLimit } = defaultLimitReq.data || {};
        dailyLimit = ZERO.plus(defaultLimit);
        dailyBalance = dailyLimit;
        singleBalance = ZERO.plus(defaultLimit);
      }

      if (!dailyLimit || !dailyBalance || !singleBalance || dailyBalance.isNaN() || singleBalance.isNaN())
        return singleMessage.error('CheckPaymentSecurity error');

      const paymentLimit = {
        isDailyLimited: !dailyLimit.eq(-1) && bigAmount.gt(dailyBalance),
        isSingleLimited: !singleBalance.eq(-1) && bigAmount.gt(singleBalance),
        dailyLimit,
        showDailyLimit: divDecimals(dailyLimit, DEFAULT_DECIMAL),
        dailyBalance,
        showDailyBalance: divDecimals(dailyBalance, DEFAULT_DECIMAL),
        singleBalance,
        showSingleBalance: divDecimals(singleBalance, DEFAULT_DECIMAL),
        defaultDailyLimit,
        defaultSingleLimit,
      };
      setPaymentLimit(paymentLimit);
      if (paymentLimit.isDailyLimited) singleMessage.error('Exceeding daily limit!');
    } catch (error) {
      singleMessage.error(handleErrorMessage(error, 'CheckPaymentSecurity error'));
    } finally {
      setLoading(false);
    }
  }, [checkLogin, paymentCount]);

  const onGuardianApprovalConfirm = useCallback(
    async (approvalInfo: GuardiansApproved[]) => {
      singleMessage.success('Approve success');
      if (openInfo?.operationType === OperationTypeEnum.communityRecovery) {
        dispatch({ type: Actions.setState, payload: { step2FinishStore: approvalInfo } });
      } else if (openInfo?.operationType === OperationTypeEnum.managerApprove) {
        const approved: IGuardiansApproved[] = approvalInfo.map(guardian => ({
          type: AccountTypeEnum[guardian.type || 'Google'],
          identifierHash: guardian.identifierHash || '',
          verificationInfo: {
            id: guardian.verifierId,
            signature: Object.values(Buffer.from(guardian.signature as any, 'hex')),
            verificationDoc: guardian.verificationDoc,
          },
        }));
        onManagerApprove(approved);
      }
      setOpenType(undefined);
    },
    [dispatch, onManagerApprove, openInfo?.operationType],
  );

  return (
    <PortkeyProvider networkType="TESTNET">
      <Header />
      <main className="p-24 pt-20 gap-2">
        <div className="flex">
          <div className="flex-1">
            <Card
              title={
                <div>
                  <span>1. identifier</span>
                  <br />
                  <a
                    className="text-xs	ml-1"
                    href="https://doc.portkey.finance/docs/What-is-a-login-account"
                    target="_blank">
                    What is a identifier?
                  </a>
                </div>
              }>
              <div className="ml-2">
                <h3>a. get identifier</h3>

                <div>
                  <Input addonBefore="Email:" onChange={e => setInputVal(e.target.value)} onBlur={onCheckEmail} />
                </div>
                <br />
                <div>
                  <span>Social Login:&nbsp;</span>
                  {socialLoginList.map(type => (
                    <span key={type}>
                      <Button
                        onClick={async () => {
                          const info = await onSocialLogin(type);
                          if (!info) return;
                          dispatch({
                            type: Actions.setIdentifierInfo,
                            payload: { identifierInfo: info },
                          });
                        }}>
                        {type}
                      </Button>
                      &nbsp;
                    </span>
                  ))}
                </div>
              </div>

              <br />
              <h3 className="ml-2">
                b. Check identifier registration status: &nbsp;<Button onClick={onValidateIdentifier}>Check</Button>
              </h3>
              <div>
                {typeof state.identifierInfo?.isLoginGuardian !== 'undefined' &&
                  !state.identifierInfo?.isLoginGuardian && (
                    <li>
                      setOriginChainId:&nbsp;
                      <Input
                        placeholder="AELF/tDVV/tDVW"
                        value={inputChainId}
                        onChange={e => setInputChainId(e.target.value)}
                        onBlur={onCheckChainId}
                      />
                    </li>
                  )}
              </div>
            </Card>

            <br />
            <Card title="2. SignUp/SignIn">
              {typeof state.step1FinishStore === 'undefined' && <div>Please finish step1</div>}
              {isSignUp && <h3>SignUp</h3>}

              {typeof state.step1FinishStore?.isLoginGuardian !== 'undefined' && (
                <div className="ml-2">
                  <span>a.&nbsp;createManager:&nbsp;</span>
                  <Button onClick={onCreateManager}>confirm</Button>
                </div>
              )}
              {isSignUp && (
                <div className="ml-2">
                  <ol>
                    <li>
                      <span>b.&nbsp;getRecommendationVerifier: &nbsp; </span>
                      <Button onClick={getRecommendationVerifier}>confirm</Button>
                    </li>
                  </ol>
                  {state.step1FinishStore && (
                    <>
                      {state.step1FinishStore?.accountType === 'Email' && (
                        <div>
                          <div>
                            <span>c.&nbsp;sendVerificationCode: &nbsp; </span>
                            <Button
                              onClick={() => {
                                if (!did.didWallet.managementAccount?.address)
                                  return singleMessage.error('Please create wallet');
                                if (!state.step1FinishStore?.identifier)
                                  return singleMessage.error('Please set step1FinishStore');
                                onSendVerificationCode({
                                  identifier: state.step1FinishStore?.identifier,
                                  operationType: OperationTypeEnum.register,
                                });
                              }}>
                              confirm
                            </Button>
                          </div>
                          <div>
                            <span>d.&nbsp;Input verificationCode: &nbsp; </span>

                            <Input value={verifierCode} max={6} onChange={e => setVerifierCode(e.target.value)} />
                          </div>
                          <div>
                            <span>e.&nbsp;verifyVerificationCode: &nbsp; </span>

                            <Button
                              onClick={async () => {
                                const identifier = state.step1FinishStore?.identifier;
                                if (!did.didWallet.managementAccount?.address)
                                  return singleMessage.error('Please create wallet');
                                if (!state.step1FinishStore) return singleMessage.error('Please set step1FinishStore');
                                if (!state.verificationStore)
                                  return singleMessage.error('Please set verificationStore');

                                if (!identifier) return singleMessage.error('Please set identifier');
                                const result = await onVerifyVerificationCode({
                                  identifier: identifier,
                                  operationType: OperationTypeEnum.register,
                                  operationDetails: JSON.stringify({
                                    manager: did.didWallet.managementAccount.address,
                                  }),
                                });
                                const verifier = state.verificationStore?.[identifier];
                                console.log('onVerifyVerificationCode:', result);
                                if (!result) return;

                                singleMessage.success('Verify success');

                                dispatch({
                                  type: Actions.setState,
                                  payload: {
                                    step2FinishStore: [
                                      {
                                        type: state.step1FinishStore.accountType,
                                        identifier: identifier,
                                        verifierId: verifier.id,
                                        verificationDoc: result.verificationDoc,
                                        signature: result.signature,
                                      },
                                    ],
                                  },
                                });
                              }}>
                              confirm
                            </Button>
                          </div>
                        </div>
                      )}
                      {state.step1FinishStore?.accountType !== 'Email' && (
                        <div>
                          <span>{`c. verify ${state.step1FinishStore?.accountType}:`} &nbsp; </span>

                          <Button onClick={onRegisterVerify}></Button>
                        </div>
                      )}
                    </>
                  )}
                </div>
              )}
              {typeof state.step1FinishStore?.isLoginGuardian !== 'undefined' &&
                state.step1FinishStore?.isLoginGuardian && (
                  <div className="ml-2">
                    <h3>SignIn</h3>
                    <div>
                      <div>
                        <span>b.&nbsp;getGuardianList:&nbsp;</span>
                        <Button
                          onClick={async () => {
                            try {
                              setLoading(true);
                              await onGetGuardianList({
                                identifier: state.step1FinishStore?.identifier,
                                chainId: state.step1FinishStore?.chainId || 'tDVW',
                              });
                            } catch (error) {
                              singleMessage.error(handleErrorMessage(error));
                            } finally {
                              setLoading(false);
                            }
                          }}>
                          confirm
                        </Button>
                      </div>
                      <div>
                        <span>c.&nbsp;guardian approve:&nbsp;</span>
                        <Button onClick={onGuardianApprove}>confirm</Button>
                      </div>
                    </div>
                  </div>
                )}
            </Card>
            <br />

            <Card title="3. SetPin and access Portkey">
              {typeof state.step2FinishStore === 'undefined' && <div>Please finish step2</div>}

              {state.step2FinishStore && (
                <div className="ml-2">
                  <div>
                    <span>SetPin:&nbsp;</span>
                    <Input onChange={e => setPin(e.target.value)} onBlur={onCheckPin} />
                  </div>
                  <br />
                  <div>
                    <Button
                      onClick={() => onCreateWallet(state.step1FinishStore?.isLoginGuardian ? 'recovery' : 'register')}>
                      {state.step1FinishStore?.isLoginGuardian ? 'Login' : 'Register'}
                    </Button>
                  </div>
                  <br />
                </div>
              )}
            </Card>
            <br />
          </div>

          <div className="flex-1 bg-slate-50 p-4 ml-4">
            <div className="break-all">
              <h2>Default config</h2>
              <Space>
                <a target="_blank" href="https://doc.portkey.finance/docs/EnvironmentalConfiguration">
                  View all Environmental config
                </a>
                <a
                  target="_blank"
                  href="https://doc.portkey.finance/docs/SDKs/CoreSDK/TypeScript/@portkeyDid#didsetconfig">
                  View all config
                </a>
              </Space>
              <br />
              <ReactJson src={DID_CONFIG} collapsed />
            </div>
            {state.identifierInfo?.identifier && (
              <div>
                <h2>identifierInfo:</h2>
                {Object.entries(state.identifierInfo).map(item =>
                  item[0] !== 'token' ? (
                    <div className="ml-2" key={item[0]}>
                      <span className="font-semibold">{`${item[0]}: `}</span>
                      <span className="break-all">
                        {typeof item[1] === 'object' ? <ReactJson src={item[1]} collapsed /> : JSON.stringify(item[1])}
                      </span>
                      <br />
                    </div>
                  ) : null,
                )}
              </div>
            )}

            {state.manager && (
              <div>
                <h2>Manager</h2>
                <div className="ml-2">
                  <div>
                    <span className="font-semibold">Address:&nbsp;</span>
                    <span className="break-all">{state.manager.address}</span>
                  </div>
                  <div>
                    <span className="font-semibold">PrivateKey:&nbsp;</span>
                    <span className="break-all">{state.manager.privateKey}</span>
                  </div>
                </div>
              </div>
            )}

            {state.verificationStore && (
              <div>
                <h2>verificationStore</h2>
                {Object.entries(state.verificationStore).map(item => {
                  console.log(typeof item[1] === 'object', 'item[1]', item[1]);
                  return (
                    <div className="ml-2" key={item[0]}>
                      <span className="font-semibold">{`${item[0]}: `}</span>
                      <span className="break-all">
                        {typeof item[1] === 'object' ? <ReactJson src={item[1]} collapsed /> : JSON.stringify(item[1])}
                      </span>
                      <br />
                    </div>
                  );
                })}
              </div>
            )}

            {state.step2FinishStore && (
              <div>
                <br />
                <h2>step2Finish</h2>
                {Object.entries(state.step2FinishStore).map(item => (
                  <div className="flex ml-2" key={item[0]}>
                    <span className="font-semibold">{`${item[0]}:`}</span>
                    &nbsp;
                    <span className="break-all">
                      {typeof item[1] === 'object' ? <ReactJson src={item[1]} collapsed /> : JSON.stringify(item[1])}
                    </span>
                    <br />
                  </div>
                ))}
              </div>
            )}
            {aaInfo && (
              <div className="break-all">
                <br />
                <h2>Portkey account</h2>
                <ReactJson src={aaInfo} />
              </div>
            )}
          </div>
        </div>

        <Card title="Common utils">
          <Row className="mb-2">
            <Col span={12}>
              <div>
                <Button onClick={onGoogleRecaptcha}>show recaptcha and get reCaptchaToken</Button>
              </div>
              {showRecaptcha && (
                <iframe
                  style={{ width: '100%', border: '0' }}
                  src={`https://openlogin-testnet.portkey.finance/recaptcha`}
                />
              )}
            </Col>
          </Row>
          <Row className="mb-2">
            <Col span={12}>
              <Space>
                <Input placeholder="Input pin" onChange={e => setPin(e.target.value)} onBlur={onCheckPin} />
                <Button
                  onClick={async () => {
                    const wallet = await did.load(pin, WALLET_KEY);
                    if (!did.didWallet.managementAccount) return singleMessage.error('Please SignIn');
                    console.log('wallet:', wallet);
                    singleMessage.success('unlock');
                  }}>
                  unlock
                </Button>
              </Space>
            </Col>

            <Col span={12}>
              <Space>
                <Button
                  onClick={async () => {
                    await did.logout({
                      chainId: 'tDVW',
                    });
                    did.config.storageMethod.removeItem(WALLET_KEY);
                    localStorage.removeItem('originChainId');
                    singleMessage.success('logout');
                  }}>
                  logout
                </Button>
              </Space>
            </Col>
          </Row>
        </Card>
        <br />
        <div className="flex mt-4">
          <Card title="Security check" className="flex-1">
            <Row className="ml-2  mb-2">
              <Col>
                <Space>
                  <Input
                    placeholder="Please enter the target chain you want to approve token."
                    value={targetChainId}
                    onChange={e => setTargetChainId(e.target.value as ChainId)}
                  />
                  <Button onClick={onCheckWalletSecurity}>Check wallet security</Button>
                </Space>
              </Col>
              <Col>
                <a
                  className="text-xs	ml-1"
                  href="https://doc.portkey.finance/docs/How-to-customise-transfer-limits"
                  target="_blank">
                  Why and how?
                </a>
                <a
                  className="text-xs	ml-1"
                  href="https://doc.portkey.finance/docs/SDKs/CoreSDK/TypeScript/@portkeyServices#servicessecurity"
                  target="_blank">
                  View doc
                </a>
              </Col>
            </Row>
            <Row className="ml-2  mb-2">
              <Col>
                <Button className="min-w-52" onClick={onGetPaymentSecurity}>
                  Get payment security list
                </Button>
              </Col>
            </Row>
            <Row className="ml-2  mb-2">
              <Col>
                <Space>
                  <Input
                    placeholder="Please enter the target chain you want to trade."
                    value={paymentCount}
                    suffix="ELF"
                    onChange={e => setPaymentCount(e.target.value as ChainId)}
                  />
                  <Button className="min-w-52" onClick={onCheckPaymentSecurity}>
                    check payment security list
                  </Button>
                </Space>
              </Col>
            </Row>
          </Card>
          <div className="flex-1 bg-slate-50 p-4 ml-4 break-all">
            {paymentLimit && (
              <div>
                <h3>PaymentLimit</h3>
                <ReactJson src={paymentLimit} collapsed />
              </div>
            )}

            {paymentSecurityList && (
              <div>
                <h3>PaymentSecurityList</h3>
                <ReactJson src={paymentSecurityList} collapsed />
              </div>
            )}
          </div>
        </div>
        <br />
        <div className="flex">
          <Card title="Contract" className="flex-1">
            <Space>
              <Button onClick={onInitContract}>Init contract</Button>
              <Button onClick={onGetBalance}>Get ELF Balance</Button>
            </Space>
            <Divider style={{ margin: '8px 0' }} />

            <Space align="start">
              <ReactJson
                name="TransferPrams"
                onEdit={edit => {
                  setTransferParams(edit.updated_src as typeof TRANSFER_PARAMS);
                }}
                src={transferParams}
                collapsed
              />

              <Button onClick={onTransfer}>Transfer</Button>
            </Space>

            <Divider style={{ margin: '8px 0' }} />
            <div>
              <div>ManagerApprove</div>
              <br />
              <Space align="start">
                <ReactJson
                  name="ApprovePrams"
                  onEdit={edit => {
                    setApproveParams(edit.updated_src as typeof APPROVE_PARAMS);
                  }}
                  src={approveParams}
                  collapsed
                />
                <Button onClick={onManagerApproveHandler}>ManagerApprove</Button>
              </Space>
            </div>
            <br />
          </Card>
          <div className="flex-1 bg-slate-50 p-4 ml-4 break-all">
            <div>
              <h3>Init contract params</h3>
              <ReactJson src={INIT_CONTRACT_PARAMS} collapsed />
            </div>
          </div>
        </div>
      </main>
      <ReCaptchaModal />
      <CommonBaseModal
        className={clsx('portkey-ui-modal-approval')}
        closable
        open={Boolean(openInfo)}
        onClose={() => setOpenType(undefined)}>
        {guardianList && (
          <GuardianApproval
            header={<div className="p-5"></div>}
            originChainId={state.step1FinishStore?.chainId || (localStorage.getItem('originChainId') as ChainId)}
            guardianList={guardianList}
            onConfirm={onGuardianApprovalConfirm}
            onError={onApprovalError}
            networkType={'TESTNET'}
            operationType={openInfo?.operationType ?? OperationTypeEnum.communityRecovery}
            operationDetails={openInfo?.operationDetails}
          />
        )}
      </CommonBaseModal>
    </PortkeyProvider>
  );
}
