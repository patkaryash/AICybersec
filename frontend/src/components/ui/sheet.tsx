import * as React from 'react';
import { Dialog as SheetPrimitive } from 'radix-ui';
import { AnimatePresence, motion, type HTMLMotionProps } from 'framer-motion';
import { X } from 'lucide-react';
import { cn } from '../../lib/utils';
import { getStrictContext } from '../../lib/get-strict-context';

type SheetContextType = {
  isOpen: boolean;
  setIsOpen: (isOpen: boolean) => void;
};

const [SheetProvider, useSheet] = getStrictContext<SheetContextType>('SheetContext');

type SheetProps = React.ComponentProps<typeof SheetPrimitive.Root>;

function Sheet({ open, defaultOpen, onOpenChange, ...props }: SheetProps) {
  const [internalOpen, setInternalOpen] = React.useState(defaultOpen ?? false);
  const isOpen = open !== undefined ? open : internalOpen;

  const setIsOpen = React.useCallback(
    (val: boolean) => {
      if (open === undefined) {
        setInternalOpen(val);
      }
      onOpenChange?.(val);
    },
    [open, onOpenChange]
  );

  return (
    <SheetProvider value={{ isOpen, setIsOpen }}>
      <SheetPrimitive.Root
        data-slot="sheet"
        open={isOpen}
        onOpenChange={setIsOpen}
        {...props}
      />
    </SheetProvider>
  );
}

type SheetTriggerProps = React.ComponentProps<typeof SheetPrimitive.Trigger>;

function SheetTrigger(props: SheetTriggerProps) {
  return <SheetPrimitive.Trigger data-slot="sheet-trigger" {...props} />;
}

type SheetCloseProps = React.ComponentProps<typeof SheetPrimitive.Close>;

function SheetClose(props: SheetCloseProps) {
  return <SheetPrimitive.Close data-slot="sheet-close" {...props} />;
}

type SheetPortalProps = React.ComponentProps<typeof SheetPrimitive.Portal>;

function SheetPortal(props: SheetPortalProps) {
  const { isOpen } = useSheet();

  return (
    <AnimatePresence>
      {isOpen && (
        <SheetPrimitive.Portal forceMount data-slot="sheet-portal" {...props} />
      )}
    </AnimatePresence>
  );
}

type SheetOverlayProps = Omit<
  React.ComponentProps<typeof SheetPrimitive.Overlay>,
  'asChild' | 'forceMount'
> &
  HTMLMotionProps<'div'>;

function SheetOverlay({
  className,
  transition = { duration: 0.25, ease: 'easeOut' },
  ...props
}: SheetOverlayProps) {
  return (
    <SheetPrimitive.Overlay asChild forceMount>
      <motion.div
        key="sheet-overlay"
        data-slot="sheet-overlay"
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        transition={transition}
        className={cn('fixed inset-0 z-50 bg-black/75 backdrop-blur-sm', className)}
        {...props}
      />
    </SheetPrimitive.Overlay>
  );
}

type Side = 'top' | 'bottom' | 'left' | 'right';

type SheetContentProps = React.ComponentProps<typeof SheetPrimitive.Content> &
  HTMLMotionProps<'div'> & {
    side?: Side;
    showCloseButton?: boolean;
  };

function SheetContent({
  side = 'left',
  transition = { type: 'spring', stiffness: 300, damping: 30 },
  className,
  children,
  showCloseButton = true,
  style,
  ...props
}: SheetContentProps) {
  const offscreen: Record<Side, { x?: string; y?: string; opacity: number }> = {
    right: { x: '100%', opacity: 0.5 },
    left: { x: '-100%', opacity: 0.5 },
    top: { y: '-100%', opacity: 0.5 },
    bottom: { y: '100%', opacity: 0.5 },
  };

  const axis = side === 'left' || side === 'right' ? 'x' : 'y';

  return (
    <SheetPortal>
      <SheetOverlay />
      <SheetPrimitive.Content asChild forceMount {...props}>
        <motion.div
          key="sheet-content"
          data-slot="sheet-content"
          data-side={side}
          initial={offscreen[side]}
          animate={{ [axis]: 0, opacity: 1 }}
          exit={offscreen[side]}
          transition={transition}
          style={style}
          className={cn(
            'fixed z-50 flex flex-col bg-[#09090B] text-zinc-100 shadow-2xl border-zinc-800 focus:outline-none',
            side === 'left' && 'inset-y-0 left-0 h-full border-r',
            side === 'right' && 'inset-y-0 right-0 h-full border-l',
            side === 'top' && 'inset-x-0 top-0 border-b',
            side === 'bottom' && 'inset-x-0 bottom-0 border-t',
            className
          )}
        >
          {children}
          {showCloseButton && (
            <SheetClose className="absolute right-4 top-4 rounded-lg p-1.5 text-zinc-400 hover:text-white hover:bg-zinc-800 focus:outline-none focus-visible:ring-2 focus-visible:ring-zinc-600 transition-colors">
              <X size={18} />
              <span className="sr-only">Close</span>
            </SheetClose>
          )}
        </motion.div>
      </SheetPrimitive.Content>
    </SheetPortal>
  );
}

function SheetHeader({ className, ...props }: React.ComponentProps<'div'>) {
  return (
    <div
      data-slot="sheet-header"
      className={cn('flex flex-col space-y-1.5 p-4', className)}
      {...props}
    />
  );
}

function SheetFooter({ className, ...props }: React.ComponentProps<'div'>) {
  return (
    <div
      data-slot="sheet-footer"
      className={cn('mt-auto flex flex-col gap-2 p-4', className)}
      {...props}
    />
  );
}

function SheetTitle(props: React.ComponentProps<typeof SheetPrimitive.Title>) {
  return (
    <SheetPrimitive.Title
      data-slot="sheet-title"
      className="text-base font-semibold text-white tracking-tight"
      {...props}
    />
  );
}

function SheetDescription(props: React.ComponentProps<typeof SheetPrimitive.Description>) {
  return (
    <SheetPrimitive.Description
      data-slot="sheet-description"
      className="text-xs text-zinc-400"
      {...props}
    />
  );
}

export {
  Sheet,
  SheetTrigger,
  SheetClose,
  SheetPortal,
  SheetOverlay,
  SheetContent,
  SheetHeader,
  SheetFooter,
  SheetTitle,
  SheetDescription,
  useSheet,
};
