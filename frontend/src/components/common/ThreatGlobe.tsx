import { useEffect, useRef, useState } from 'react';
import Globe, { GlobeMethods } from 'react-globe.gl';

export default function ThreatGlobe() {
  const globeRef = useRef<GlobeMethods | any>(undefined);
  const containerRef = useRef<HTMLDivElement>(null);
  const [dimensions, setDimensions] = useState({ width: 0, height: 0 });

  useEffect(() => {
    const handleResize = () => {
      if (containerRef.current) {
        setDimensions({
          width: containerRef.current.offsetWidth,
          height: containerRef.current.offsetHeight,
        });
      }
    };

    handleResize();
    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, []);

  useEffect(() => {
    if (globeRef.current && globeRef.current.controls) {
      const controls = globeRef.current.controls();
      if (controls) {
        controls.autoRotate = true;
        controls.autoRotateSpeed = 0.8;
      }
      if (globeRef.current.pointOfView) {
        globeRef.current.pointOfView({ lat: 20, lng: 0, altitude: 2.5 });
      }
    }
  }, [dimensions]);

  const arcsData = [
    { startLat: 37.77, startLng: -122.41, endLat: 51.50, endLng: -0.12, color: '#F43F5E' }, // SF -> London
    { startLat: 35.68, startLng: 139.69, endLat: 40.71, endLng: -74.00, color: '#F97316' }, // Tokyo -> NY
    { startLat: 28.61, startLng: 77.20, endLat: 51.50, endLng: -0.12, color: '#8B5CF6' },   // Delhi -> London
    { startLat: 1.35, startLng: 103.82, endLat: 37.77, endLng: -122.41, color: '#06B6D4' },  // Singapore -> SF
  ];

  const pointsData = [
    { lat: 37.77, lng: -122.41, color: '#F43F5E', size: 0.6 },
    { lat: 51.50, lng: -0.12, color: '#F43F5E', size: 0.6 },
    { lat: 35.68, lng: 139.69, color: '#F97316', size: 0.5 },
    { lat: 40.71, lng: -74.00, color: '#F97316', size: 0.5 },
    { lat: 28.61, lng: 77.20, color: '#8B5CF6', size: 0.5 },
    { lat: 1.35, lng: 103.82, color: '#06B6D4', size: 0.5 },
  ];

  return (
    <div
      ref={containerRef}
      className="w-full h-full min-h-[300px] flex items-center justify-center overflow-hidden"
    >
      {dimensions.width > 0 && dimensions.height > 0 && (
        <Globe
          ref={globeRef}
          width={dimensions.width}
          height={dimensions.height}
          backgroundColor="rgba(0,0,0,0)"
          globeImageUrl="//unpkg.com/three-globe/example/img/earth-blue-marble.jpg"
          bumpImageUrl="//unpkg.com/three-globe/example/img/earth-topology.png"
          atmosphereColor="#8B5CF6"
          atmosphereAltitude={0.18}
          arcsData={arcsData}
          arcColor="color"
          arcDashLength={0.4}
          arcDashGap={0.2}
          arcDashAnimateTime={1600}
          arcStroke={0.6}
          pointsData={pointsData}
          pointColor="color"
          pointAltitude={0.02}
          pointRadius="size"
        />
      )}
    </div>
  );
}
