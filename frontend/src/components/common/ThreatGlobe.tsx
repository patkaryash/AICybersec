// src/components/common/ThreatGlobe.tsx
import { useEffect, useRef, useState } from 'react';
import Globe from 'react-globe.gl';

// Placeholder threat data per country (ISO A3 code → threat score 0-100)
const COUNTRY_THREAT_DATA: Record<string, number> = {
    USA: 85, GBR: 62, DEU: 45, FRA: 38, IND: 78,
    CHN: 92, RUS: 88, BRA: 55, JPN: 30, AUS: 25,
    CAN: 40, ZAF: 47, NGA: 52, MEX: 60, ITA: 35,
    ESP: 33, KOR: 28, IDN: 65, TUR: 58, EGY: 51,
};

function getThreatColor(score: number): string {
    if (score >= 80) return '#ef4444';
    if (score >= 60) return '#f97316';
    if (score >= 40) return '#f59e0b';
    if (score >= 20) return '#84cc16';
    return '#10b981';
}

export default function ThreatGlobe() {
    const globeRef = useRef<any>(undefined);
    const containerRef = useRef<HTMLDivElement>(null);
    const [dimensions, setDimensions] = useState({ width: 0, height: 0 });
    const [countries, setCountries] = useState<any[]>([]);
    const [hoveredCountry, setHoveredCountry] = useState<any>(null);
    const [dataLoaded, setDataLoaded] = useState(false);

    // 1. Responsive sizing
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

    // 2. Fetch country GeoJSON data
    useEffect(() => {
        fetch('https://raw.githubusercontent.com/vasturiano/globe.gl/master/example/datasets/ne_110m_admin_0_countries.geojson')
            .then((res) => res.json())
            .then((data) => {
                const enriched = data.features.map((f: any) => ({
                    ...f,
                    threatScore: COUNTRY_THREAT_DATA[f.properties.ISO_A3] ?? 0,
                }));
                setCountries(enriched);
                setDataLoaded(true);
            })
            .catch((err) => {
                console.error('Failed to load country data:', err);
                setDataLoaded(true);
            });
    }, []);

    // 3. Auto-rotate after data loads
    useEffect(() => {
        if (globeRef.current && dataLoaded) {
            globeRef.current.controls().autoRotate = true;
            globeRef.current.controls().autoRotateSpeed = 0.5;
            globeRef.current.pointOfView({ lat: 20, lng: 0, altitude: 2.2 });
        }
    }, [dataLoaded]);

    return (
        <div
            ref={containerRef}
            style={{ width: '100%', height: '100%', minHeight: '300px', position: 'relative' }}
        >
            {/* Loading indicator */}
            {!dataLoaded && (
                <div style={{
                    position: 'absolute', inset: 0, display: 'flex',
                    alignItems: 'center', justifyContent: 'center',
                    color: '#64748b', fontSize: '11px', fontFamily: 'monospace',
                    zIndex: 10,
                }}>
                    Loading country data...
                </div>
            )}

            {/* Hover tooltip */}
            {hoveredCountry && (
                <div style={{
                    position: 'absolute', top: 10, left: 10, zIndex: 10,
                    padding: '8px 12px',
                    background: 'rgba(11, 15, 25, 0.9)',
                    border: '1px solid #1e293b',
                    borderRadius: '6px',
                    fontFamily: 'monospace', fontSize: '11px',
                    color: '#e2e8f0', pointerEvents: 'none',
                }}>
                    <div style={{ color: '#22d3ee', fontWeight: 'bold' }}>
                        {hoveredCountry.properties?.NAME || 'Unknown'}
                    </div>
                    <div>Threat Score: {hoveredCountry.threatScore}</div>
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
                    atmosphereColor="#8A2BE2"
                    atmosphereAltitude={0.15}
                    polygonsData={countries}
                    polygonCapColor={(d: any) =>
                        d.threatScore > 0 ? getThreatColor(d.threatScore) : 'rgba(30, 41, 59, 0.4)'
                    }
                    polygonSideColor={() => 'rgba(0, 0, 0, 0)'}
                    polygonStrokeColor={() => '#1e293b'}
                    polygonAltitude={(d: any) => (d.threatScore > 0 ? 0.01 : 0.005)}
                    onPolygonHover={(polygon: any) => setHoveredCountry(polygon)}
                    onPolygonClick={(polygon: any) => {
                        if (polygon && globeRef.current) {
                            const lat = polygon.properties?.LABEL_Y ?? 0;
                            const lng = polygon.properties?.LABEL_X ?? 0;
                            globeRef.current.pointOfView({ lat, lng, altitude: 1.5 }, 1000);
                        }
                    }}
                />
            )}
        </div>
    );
}