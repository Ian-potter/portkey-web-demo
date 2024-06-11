import dynamic from 'next/dynamic';

export default dynamic(() => import('../page-components/Home/index'), { ssr: false });
