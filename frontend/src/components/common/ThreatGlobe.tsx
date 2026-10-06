// src/components/common/ThreatGlobe.tsx
import { useEffect, useRef, useState } from 'react';
import Globe from 'react-globe.gl';

// Country threat telemetry scoring (ISO A3 code → threat index 0-100)
const COUNTRY_THREAT_DATA: Record<string, number> = {
  USA: 85, GBR: 62, DEU: 45, FRA: 38, IND: 78,
  CHN: 92, RUS: 88, BRA: 55, JPN: 30, AUS: 25,
  CAN: 40, ZAF: 47, NGA: 52, MEX: 60, ITA: 35,
  ESP: 33, KOR: 28, IDN: 65, TUR: 58, EGY: 51,
};

function getThreatColor(score: number): string {
  if (score >= 80) return 'rgba(220, 38, 38, 0.75)';   // Critical Red
  if (score >= 60) return 'rgba(234, 88, 12, 0.75)';   // High Orange
  if (score >= 40) return 'rgba(202, 138, 4, 0.75)';   // Medium Amber
  if (score >= 20) return 'rgba(13, 148, 136, 0.65)';  // Low Teal
  return 'rgba(5, 150, 105, 0.65)';                   // Info Emerald
}

// Enterprise telemetry recon pathways
const TELEMETRY_ARCS = [
  { startLat: 50.1109, startLng: 8.6821, endLat: 39.0438, endLng: -77.4874, color: ['#2563EB', '#60A5FA'] },
  { startLat: 51.5074, startLng: -0.1278, endLat: 1.3521, endLng: 103.8198, color: ['#6D5DFB', '#38BDF8'] },
  { startLat: 39.0438, startLng: -77.4874, endLat: 35.6762, endLng: 139.6503, color: ['#2563EB', '#818CF8'] },
  { startLat: 50.1109, startLng: 8.6821, endLat: -33.8688, endLng: 151.2093, color: ['#0891B2', '#60A5FA'] },
  { startLat: 39.0438, startLng: -77.4874, endLat: 50.1109, endLng: 8.6821, color: ['#3B82F6', '#93C5FD'] },
];

const TELEMETRY_RINGS = [
  { lat: 50.1109, lng: 8.6821, maxRadius: 3.5, propagationSpeed: 1.8, repeatPeriod: 1600 },
  { lat: 39.0438, lng: -77.4874, maxRadius: 4.0, propagationSpeed: 2.0, repeatPeriod: 1400 },
  { lat: 1.3521, lng: 103.8198, maxRadius: 3.2, propagationSpeed: 1.5, repeatPeriod: 1800 },
  { lat: 35.6762, lng: 139.6503, maxRadius: 3.8, propagationSpeed: 1.9, repeatPeriod: 1500 },
];

const TELEMETRY_NODES = [
  { lat: 50.1109, lng: 8.6821, size: 0.35, color: '#38BDF8', label: 'Frankfurt Recon Hub' },
  { lat: 39.0438, lng: -77.4874, size: 0.4, color: '#60A5FA', label: 'US-East Target Probe' },
  { lat: 1.3521, lng: 103.8198, size: 0.35, color: '#A78BFA', label: 'APAC Perimeter Gate' },
  { lat: 35.6762, lng: 139.6503, size: 0.35, color: '#38BDF8', label: 'Tokyo Edge Sensor' },
  { lat: 51.5074, lng: -0.1278, size: 0.35, color: '#60A5FA', label: 'London Ingress Filter' },
  { lat: -33.8688, lng: 151.2093, size: 0.3, color: '#38BDF8', label: 'Sydney Cloud Relay' },
];

// Module-level GeoJSON cache to prevent re-fetching on tab switches
let cachedCountriesData: any[] | null = null;

export default function ThreatGlobe() {
  const globeRef = useRef<any>(undefined);
  const containerRef = useRef<HTMLDivElement>(null);
  const [dimensions, setDimensions] = useState({ width: 0, height: 0 });
  const [countries, setCountries] = useState<any[]>(cachedCountriesData || []);
  const [hoveredCountry, setHoveredCountry] = useState<any>(null);
  const [hoveredNode, setHoveredNode] = useState<any>(null);
  const [dataLoaded, setDataLoaded] = useState(Boolean(cachedCountriesData));

  // 1. Responsive sizing with ResizeObserver
  useEffect(() => {
    if (!containerRef.current) return;
    const updateSize = () => {
      if (containerRef.current) {
        setDimensions({
          width: containerRef.current.offsetWidth,
          height: containerRef.current.offsetHeight,
        });
      }
    };
    updateSize();

    const observer = new ResizeObserver(() => {
      updateSize();
    });
    observer.observe(containerRef.current);

    return () => observer.disconnect();
  }, []);

  // 2. Fetch country GeoJSON data with in-memory caching
  useEffect(() => {
    if (cachedCountriesData) {
      return;
    }

    let isMounted = true;
    fetch('https://raw.githubusercontent.com/vasturiano/globe.gl/master/example/datasets/ne_110m_admin_0_countries.geojson')
      .then((res) => res.json())
      .then((data) => {
        const enriched = data.features.map((f: any) => ({
          ...f,
          threatScore: COUNTRY_THREAT_DATA[f.properties.ISO_A3] ?? 0,
        }));
        cachedCountriesData = enriched;
        if (isMounted) {
          setCountries(enriched);
          setDataLoaded(true);
        }
      })
      .catch((err) => {
        console.error('Failed to load country telemetry data:', err);
        if (isMounted) {
          setDataLoaded(true);
        }
      });

    return () => {
      isMounted = false;
    };
  }, []);

  // 3. Smooth auto-rotation & point-of-view configuration
  useEffect(() => {
    if (globeRef.current && dataLoaded) {
      try {
        const controls = globeRef.current.controls();
        if (controls) {
          controls.autoRotate = true;
          controls.autoRotateSpeed = 0.55;
          controls.enableZoom = false; // Prevent accidental wheel zoom hijacking page scroll
        }
        globeRef.current.pointOfView({ lat: 20, lng: 10, altitude: 2.1 });
      } catch {
        // Fallback gracefully if WebGL context was busy
      }
    }
  }, [dataLoaded]);

  return (
    <div
      ref={containerRef}
      className="w-full h-full min-h-[300px] relative flex items-center justify-center overflow-hidden"
    >
      {/* Loading state */}
      {!dataLoaded && (
        <div className="absolute inset-0 flex items-center justify-center text-slate-400 font-mono text-[11px] z-10">
          <span>INITIALIZING 3D THREAT TELEMETRY...</span>
        </div>
      )}

      {/* Interactive hover tooltip for country */}
      {hoveredCountry && (
        <div className="absolute top-3 left-3 z-30 px-3.5 py-2.5 rounded-xl bg-[#0B1F3A]/95 border border-[#1D4ED8]/40 shadow-2xl text-xs font-mono backdrop-blur-md pointer-events-none transition-all duration-150">
          <div className="text-sky-300 font-bold flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-sky-400 animate-pulse" />
            <span>{hoveredCountry.properties?.NAME || 'Target Zone'}</span>
          </div>
          <div className="text-slate-300 mt-1 flex items-center gap-2">
            <span>Threat Exposure:</span>
            <span className="font-bold text-white px-1.5 py-0.2 rounded bg-[#152E54] border border-[#1D4ED8]/30">
              {hoveredCountry.threatScore} / 100
            </span>
          </div>
        </div>
      )}

      {/* Interactive hover tooltip for sensor node */}
      {hoveredNode && (
        <div className="absolute bottom-3 left-3 z-30 px-3.5 py-2.5 rounded-xl bg-[#0B1F3A]/95 border border-sky-400/40 shadow-2xl text-xs font-mono backdrop-blur-md pointer-events-none transition-all duration-150">
          <div className="text-sky-300 font-bold flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-sky-400 animate-ping" />
            <span>{hoveredNode.label}</span>
          </div>
          <div className="text-slate-300 mt-1 text-[11px]">
            Coords: <span className="text-white">{hoveredNode.lat.toFixed(2)}°, {hoveredNode.lng.toFixed(2)}°</span>
          </div>
        </div>
      )}

      {dimensions.width > 0 && (
        <Globe
          ref={globeRef}
          width={dimensions.width}
          height={dimensions.height}
          backgroundColor="rgba(0,0,0,0)"
          globeImageUrl="//unpkg.com/three-globe/example/img/earth-dark.jpg"
          bumpImageUrl="//unpkg.com/three-globe/example/img/earth-topology.png"
          atmosphereColor="#1D4ED8"
          atmosphereAltitude={0.22}
          arcsData={TELEMETRY_ARCS}
          arcColor="color"
          arcDashLength={0.4}
          arcDashGap={0.2}
          arcDashAnimateTime={2200}
          arcStroke={0.6}
          ringsData={TELEMETRY_RINGS}
          ringColor={() => (t: number) => `rgba(29, 78, 216, ${Math.max(0, 0.8 * (1 - t))})`}
          ringMaxRadius="maxRadius"
          ringPropagationSpeed="propagationSpeed"
          ringRepeatPeriod="repeatPeriod"
          pointsData={TELEMETRY_NODES}
          pointColor="color"
          pointAltitude={0.03}
          pointRadius="size"
          onPointHover={(point: any) => setHoveredNode(point)}
          onPointClick={(point: any) => {
            if (point && globeRef.current) {
              globeRef.current.pointOfView({ lat: point.lat, lng: point.lng, altitude: 1.6 }, 1000);
            }
          }}
          polygonsData={countries}
          polygonCapColor={(d: any) =>
            d.threatScore > 0 ? getThreatColor(d.threatScore) : 'rgba(15, 23, 42, 0.65)'
          }
          polygonSideColor={() => 'rgba(0, 0, 0, 0)'}
          polygonStrokeColor={() => '#1E293B'}
          polygonAltitude={(d: any) => (d.threatScore > 0 ? 0.012 : 0.005)}
          onPolygonHover={(polygon: any) => setHoveredCountry(polygon)}
          onPolygonClick={(polygon: any) => {
            if (polygon && globeRef.current) {
              const lat = polygon.properties?.LABEL_Y ?? 0;
              const lng = polygon.properties?.LABEL_X ?? 0;
              globeRef.current.pointOfView({ lat, lng, altitude: 1.6 }, 1000);
            }
          }}
        />
      )}
    </div>
  );
}