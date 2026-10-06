/**
 * Shared framer-motion animation variant presets.
 * Typed correctly for framer-motion v14 strict Easing union.
 */
import type { Variants } from 'framer-motion';

/** Stagger container */
export const containerVariants: Variants = {
  hidden: { opacity: 0 },
  visible: {
    opacity: 1,
    transition: {
      staggerChildren: 0.08,
      delayChildren: 0.05,
    },
  },
};

/** Individual stagger child */
export const itemVariants: Variants = {
  hidden: { opacity: 0, y: 12 },
  visible: {
    opacity: 1,
    y: 0,
    transition: { duration: 0.35, ease: 'easeOut' as const },
  },
};
