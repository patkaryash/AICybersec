import { useState, useEffect } from 'react';

export function useTimer(startedAt: string, completedAt?: string, isRunning: boolean = true) {
  const [elapsedSeconds, setElapsedSeconds] = useState<number>(0);

  useEffect(() => {
    const calculateSeconds = () => {
      const start = new Date(startedAt).getTime();
      const end = completedAt ? new Date(completedAt).getTime() : Date.now();
      const diff = Math.max(0, Math.floor((end - start) / 1000));
      setElapsedSeconds(diff);
    };

    calculateSeconds();

    if (!isRunning || completedAt) {
      return;
    }

    const interval = setInterval(calculateSeconds, 1000);
    return () => clearInterval(interval);
  }, [startedAt, completedAt, isRunning]);

  const formatTime = (totalSeconds: number): string => {
    const hours = Math.floor(totalSeconds / 3600);
    const minutes = Math.floor((totalSeconds % 3600) / 60);
    const seconds = totalSeconds % 60;

    const pad = (n: number) => n.toString().padStart(2, '0');

    if (hours > 0) {
      return `${pad(hours)}:${pad(minutes)}:${pad(seconds)}`;
    }
    return `${pad(minutes)}:${pad(seconds)}`;
  };

  return {
    elapsedSeconds,
    formattedTime: formatTime(elapsedSeconds),
  };
}
