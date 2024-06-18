import BigNumber from 'bignumber.js';

export const PASSWORD_LENGTH = 6;

export const ZERO = new BigNumber(0);

export const isEffectiveNumber = (v: any) => {
  const val = new BigNumber(v);
  return !val.isNaN() && !val.lte(0);
};
