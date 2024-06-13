import { Menu, MenuProps } from 'antd';
import React, { useMemo } from 'react';
import { GITHUB_ICON } from './constants';
import Image from 'next/image';

export default function Header() {
  const items = useMemo(
    () => [
      {
        label: '',
        key: 'mail',
        icon: (
          <a
            href="https://github.com/Portkey-Wallet/portkey-web-demo"
            target="_blank"
            className="text-black"
            rel="noopener noreferrer">
            <Image width={24} height={24} src={GITHUB_ICON} alt="github" />
          </a>
        ),
      },
      {
        key: 'Docs',
        label: (
          <a href="https://doc.portkey.finance" target="_blank" className="text-black" rel="noopener noreferrer">
            Docs
          </a>
        ),
      },
    ],
    [],
  );

  return (
    <div className="flex px-24 justify-between py-3.5 items-center shadow-xl	mb-3 fixed w-full z-[500] bg-white	">
      <div>
        <Image width={30} height={30} src={'Portkey.svg'} alt="Portkey logo" />
      </div>

      <ul className="flex m-0">
        {items.map(item => (
          <li className="flex items-center px-2.5 text-lg	" key={item?.key}>
            <div>{item?.icon}</div>
            <div>{item?.label}</div>
          </li>
        ))}
      </ul>
    </div>
  );
}
