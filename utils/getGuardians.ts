import { ChainId, ChainType } from '@portkey/types';
import { VerifierItem, did } from '@portkey/did';
import { AccountType, Guardian } from '@portkey/services';

interface IGetGuardiansProps {
  chainId: ChainId;
  identifier?: string;
  caHash?: string;
}

export const getVerifierList = (chainId: ChainId) => {
  return did.getVerifierServers(chainId);
};

export const getGuardianList = async ({ identifier, chainId, caHash }: IGetGuardiansProps) => {
  if (!(caHash || identifier)) throw 'Param is not valid';
  const verifierList = await getVerifierList(chainId);
  if (!verifierList) throw new Error('Fetch verifier list error');
  const verifierMap: { [x: string]: VerifierItem } = {};
  verifierList.forEach(item => {
    verifierMap[item.id] = item;
  });

  const params = identifier
    ? {
        loginGuardianIdentifier: identifier.replaceAll(/\s/g, ''),
      }
    : {
        caHash,
      };

  const payload = await did.getHolderInfo(Object.assign(params, { chainId }));

  const { guardians } = payload?.guardianList ?? { guardians: [] };

  return guardians.map(_guardianAccount => {
    const key = `${_guardianAccount.guardianIdentifier}&${_guardianAccount.verifierId}`;

    const guardianAccount = _guardianAccount.guardianIdentifier || _guardianAccount.identifierHash;
    const verifier = verifierMap?.[_guardianAccount.verifierId];

    const baseGuardian: Guardian & {
      verifier?: VerifierItem;
      key: string;
      identifier: string;
      guardianType: AccountType;
    } = {
      ..._guardianAccount,
      key,
      verifier,
      identifier: guardianAccount,
      guardianType: _guardianAccount.type,
    };

    return baseGuardian;
  });
};
