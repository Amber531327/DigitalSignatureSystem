import React from 'react';
import '../styles/globals.css';

type AppProps = {
  Component: React.ComponentType<any>;
  pageProps: any;
};

function MyApp({ Component, pageProps }: AppProps) {
  return <Component {...pageProps} />;
}

export default MyApp; 