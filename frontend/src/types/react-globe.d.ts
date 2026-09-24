declare module 'react-globe.gl' {
  import { ComponentType, MutableRefObject } from 'react';

  export interface GlobeMethods {
    pointOfView: (coords: { lat?: number; lng?: number; altitude?: number }, ms?: number) => void;
    controls: () => {
      autoRotate: boolean;
      autoRotateSpeed: number;
      enableZoom?: boolean;
    };
  }

  export interface GlobeProps {
    ref?: any;
    width?: number;
    height?: number;
    backgroundColor?: string;
    globeImageUrl?: string;
    bumpImageUrl?: string;
    atmosphereColor?: string;
    atmosphereAltitude?: number;
    arcsData?: any[];
    arcColor?: any;
    arcDashLength?: number;
    arcDashGap?: number;
    arcDashAnimateTime?: number;
    arcStroke?: number;
    pointsData?: any[];
    pointColor?: any;
    pointAltitude?: number;
    pointRadius?: any;
    [key: string]: any;
  }

  const Globe: ComponentType<GlobeProps>;
  export default Globe;
}
