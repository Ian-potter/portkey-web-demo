import { useCallback, useEffect, useRef } from 'react';
import { LoginResult, RegisterResult, did } from '@portkey/did';
import { ChainId } from '@portkey/types';
import { AccountType, GuardiansApproved, RecoverStatusResult, RegisterStatusResult } from '@portkey/services';
import { AddManagerType, handleErrorMessage, setLoading, singleMessage } from '@portkey/did-ui-react';
import { getExtraData, randomId } from '@portkey/utils';

interface CreateWalletParams {
  pin: string;
  type: AddManagerType;
  chainId: ChainId;
  accountType: AccountType;
  guardianIdentifier: string;
  guardianApprovedList: GuardiansApproved[];
}

export function useLoginWallet() {
  const getRequestStatus = useCallback(
    async ({ sessionId, chainId, type }: { sessionId: string; chainId: ChainId; type: AddManagerType }) => {
      let status, error: Error | undefined;
      try {
        if (type === 'register') {
          status = await did.didWallet.getRegisterStatus({
            sessionId,
            chainId,
          });
          const { registerStatus } = status;

          if (registerStatus !== 'pass') {
            throw new Error((status as RegisterStatusResult).registerMessage);
          }
        } else {
          status = await did.didWallet.getLoginStatus({ sessionId, chainId });
          const { recoveryStatus } = status;

          if (recoveryStatus !== 'pass') {
            throw new Error((status as RecoverStatusResult).recoveryMessage);
          }
        }
      } catch (e: any) {
        error = e;
      }
      return { sessionId, status, error };
    },
    [],
  );

  const requestRegisterWallet = useCallback(
    async ({ pin, type, chainId, accountType, guardianIdentifier, guardianApprovedList }: CreateWalletParams) => {
      if (!guardianIdentifier || !accountType) throw 'Missing account!!! Please login/register again';
      if (!guardianApprovedList?.length) throw 'Missing guardianApproved';
      const wallet = did.didWallet;

      if (!wallet || !wallet.managementAccount?.address)
        throw 'ManagementAccount information is not detected, please initialize management information `did.create`';
      const managerAddress = wallet.managementAccount!.address;
      const requestId = randomId();

      const clientId = managerAddress;

      const registerVerifier = guardianApprovedList[0];
      const extraData = await getExtraData();
      const params = {
        type: accountType,
        loginGuardianIdentifier: guardianIdentifier.replaceAll(/\s/g, ''),
        extraData,
        chainId,
        verifierId: registerVerifier.verifierId,
        verificationDoc: registerVerifier.verificationDoc,
        signature: registerVerifier.signature,
        context: {
          clientId,
          requestId,
        },
      };

      const { sessionId } = await did.services.register({
        ...params,
        manager: managerAddress,
      });

      return getRequestStatus({
        chainId,
        sessionId,
        type: 'register',
      }) as Promise<RegisterResult>;
    },
    [getRequestStatus],
  );

  const requestRecoveryWallet = useCallback(
    async ({ pin, chainId, accountType, guardianIdentifier, guardianApprovedList, type }: CreateWalletParams) => {
      if (!guardianIdentifier || !accountType) throw 'Missing account!!! Please login/register again';

      const wallet = did.didWallet;
      if (!wallet || !wallet.managementAccount?.address)
        throw 'ManagementAccount information is not detected, please initialize management information `did.create`';
      const managerAddress = wallet.managementAccount!.address;
      const requestId = randomId();

      const clientId = managerAddress;

      const extraData = await getExtraData();

      const _guardianApprovedList = guardianApprovedList.filter(item =>
        Boolean(item.signature && item.verificationDoc),
      );

      const params = {
        loginGuardianIdentifier: guardianIdentifier.replaceAll(/\s/g, ''),
        guardiansApproved: _guardianApprovedList,
        extraData,
        chainId,
        context: {
          clientId,
          requestId,
        },
      };

      const { sessionId } = await did.services.recovery({
        ...params,
        manager: managerAddress,
      });

      return getRequestStatus({
        chainId,
        sessionId,
        type: 'recovery',
      }) as Promise<LoginResult>;
    },
    [getRequestStatus],
  );

  const createWallet = useCallback(
    async ({ pin, type, chainId, accountType, guardianIdentifier, guardianApprovedList }: CreateWalletParams) => {
      try {
        if (!guardianIdentifier) throw 'Missing account!!!';

        const loadingText =
          type === 'recovery' ? 'Initiating social recovery...' : 'Creating a wallet address on the blockchain';
        if (!did.didWallet.managementAccount) {
          throw Error(`Management information not detected, please "did.create" before`);
        }
        setLoading(true, loadingText);

        let walletResult: RegisterResult | LoginResult;
        const walletParams = {
          pin,
          type,
          chainId,
          accountType,
          guardianIdentifier,
          guardianApprovedList,
        };
        if (type === 'register') {
          walletResult = await requestRegisterWallet(walletParams);
        } else if (type === 'recovery') {
          walletResult = await requestRecoveryWallet(walletParams);
        } else {
          throw 'Param "type" error';
        }

        if (walletResult.error) throw walletResult.error;

        if (!walletResult.status?.caAddress || !walletResult.status?.caHash) {
          throw Error('Can not get wallet result');
        }
        const wallet = did.didWallet.managementAccount!.wallet;
        setLoading(false);
        return {
          caInfo: {
            caAddress: walletResult.status.caAddress,
            caHash: walletResult.status.caHash,
          },
          accountInfo: {
            managerUniqueId: walletResult.sessionId,
            guardianIdentifier,
            accountType,
            type,
          },
          createType: type,
          chainId,
          pin,
          walletInfo: wallet,
        };
      } catch (error: any) {
        setLoading(false);
        singleMessage.error(handleErrorMessage(error));
      }
    },
    [requestRegisterWallet, requestRecoveryWallet],
  );

  return createWallet;
}
