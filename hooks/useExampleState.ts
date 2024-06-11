import { useReducer } from 'react';
import { AccountType, GuardiansApproved } from '@portkey/services';
import { ChainId, IBlockchainWallet } from '@portkey/types';
import { VerifierItem } from '@portkey/did';
import { IGuardianIdentifierInfo } from '@portkey/did-ui-react';

export enum Actions {
  setIdentifierInfo = 'setIdentifierInfo',
  changeIdentifierInfo = 'changeIdentifierInfo',
  setState = 'setState',
  changeVerificationStore = 'changeVerificationStore',
  destroy = 'DESTROY',
}

export type State = {
  identifierInfo?: {
    token?: string;
    accountType?: AccountType;
    identifier?: string;
    isLoginGuardian?: boolean;
    originChainId?: ChainId;
  };
  verificationStore?: Record<string, VerifierItem & { verifierSessionId?: string }>;
  manager?: IBlockchainWallet;
  guardianApproved?: GuardiansApproved[];
  step1FinishStore?: IGuardianIdentifierInfo;
  step2FinishStore?: GuardiansApproved[];
  needGoogleRecaptcha?: boolean;
  reCaptchaToken?: string;
};

//reducer
function reducer(state: State, { type, payload }: { type: Actions; payload: any }) {
  switch (type) {
    case Actions.destroy: {
      return {};
    }
    case Actions.setState: {
      return Object.assign({}, state, payload);
    }
    case Actions.changeIdentifierInfo: {
      return Object.assign({}, state, { identifierInfo: { ...state.identifierInfo, ...payload.identifierInfo } });
    }
    case Actions.changeVerificationStore: {
      return Object.assign({}, state, {
        verificationStore: { ...state.verificationStore, ...payload.verificationStore },
      });
    }
    default: {
      const { destroy } = payload;
      if (destroy) return Object.assign({}, payload);
      return Object.assign({}, state, payload);
    }
  }
}
export function useExampleState(): [State, (actions: { type: Actions; payload: State }) => void] {
  const [state, dispatch]: [State, (actions: { type: Actions; payload: State }) => void] = useReducer(reducer, {});
  return [state, dispatch];
}
