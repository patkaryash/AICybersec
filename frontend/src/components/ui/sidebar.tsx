import * as React from 'react';
import { Slot } from 'radix-ui';
import { cva, type VariantProps } from 'class-variance-authority';
import { PanelLeft } from 'lucide-react';
import type { Transition } from 'framer-motion';

import { useIsMobile } from '../../hooks/use-mobile';
import { cn } from '../../lib/utils';
import { getStrictContext } from '../../lib/get-strict-context';
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from './sheet';
import {
  TooltipProvider,
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from './tooltip';
import { Highlight, HighlightItem } from './highlight';

const SIDEBAR_COOKIE_NAME = 'sidebar_state';
const SIDEBAR_COOKIE_MAX_AGE = 60 * 60 * 24 * 7; // 7 days
const SIDEBAR_WIDTH = '16rem';
const SIDEBAR_WIDTH_ICON = '3.5rem';
const SIDEBAR_KEYBOARD_SHORTCUT = 'b';

type SidebarContextProps = {
  state: 'expanded' | 'collapsed';
  open: boolean;
  setOpen: (open: boolean) => void;
  openMobile: boolean;
  setOpenMobile: (open: boolean) => void;
  isMobile: boolean;
  toggleSidebar: () => void;
};

const [LocalSidebarProvider, useSidebar] =
  getStrictContext<SidebarContextProps>('SidebarContext');

export type SidebarProviderProps = React.ComponentProps<'div'> & {
  defaultOpen?: boolean;
  open?: boolean;
  onOpenChange?: (open: boolean) => void;
};

function SidebarProvider({
  defaultOpen = true,
  open: openProp,
  onOpenChange: setOpenProp,
  className,
  style,
  children,
  ...props
}: SidebarProviderProps) {
  const isMobile = useIsMobile();
  const [openMobile, setOpenMobile] = React.useState(false);

  // Read initial cookie if available
  const [internalOpen, setInternalOpen] = React.useState<boolean>(() => {
    if (typeof document !== 'undefined') {
      const match = document.cookie.match(new RegExp(`(^| )${SIDEBAR_COOKIE_NAME}=([^;]+)`));
      if (match) {
        return match[2] === 'true';
      }
    }
    return defaultOpen;
  });

  const open = openProp ?? internalOpen;

  const setOpen = React.useCallback(
    (value: boolean | ((value: boolean) => boolean)) => {
      const openState = typeof value === 'function' ? value(open) : value;
      if (setOpenProp) {
        setOpenProp(openState);
      } else {
        setInternalOpen(openState);
      }

      if (typeof document !== 'undefined') {
        document.cookie = `${SIDEBAR_COOKIE_NAME}=${openState}; path=/; max-age=${SIDEBAR_COOKIE_MAX_AGE}; SameSite=Lax`;
      }
    },
    [setOpenProp, open]
  );

  const toggleSidebar = React.useCallback(() => {
    return isMobile ? setOpenMobile((prev) => !prev) : setOpen((prev) => !prev);
  }, [isMobile, setOpen, setOpenMobile]);

  // Keyboard shortcut (Cmd+B or Ctrl+B)
  React.useEffect(() => {
    const handleKeyDown = (event: KeyboardEvent) => {
      if (
        event.key.toLowerCase() === SIDEBAR_KEYBOARD_SHORTCUT &&
        (event.metaKey || event.ctrlKey)
      ) {
        event.preventDefault();
        toggleSidebar();
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [toggleSidebar]);

  const state = open ? 'expanded' : 'collapsed';

  const contextValue = React.useMemo<SidebarContextProps>(
    () => ({
      state,
      open,
      setOpen,
      isMobile,
      openMobile,
      setOpenMobile,
      toggleSidebar,
    }),
    [state, open, setOpen, isMobile, openMobile, setOpenMobile, toggleSidebar]
  );

  return (
    <LocalSidebarProvider value={contextValue}>
      <TooltipProvider delayDuration={0}>
        <div
          data-slot="sidebar-wrapper"
          style={
            {
              '--sidebar-width': SIDEBAR_WIDTH,
              '--sidebar-width-icon': SIDEBAR_WIDTH_ICON,
              ...style,
            } as React.CSSProperties
          }
          className={cn(
            'group/sidebar-wrapper flex min-h-screen w-full relative',
            className
          )}
          {...props}
        >
          {children}
        </div>
      </TooltipProvider>
    </LocalSidebarProvider>
  );
}

export type SidebarProps = React.ComponentProps<'div'> & {
  side?: 'left' | 'right';
  variant?: 'sidebar' | 'floating' | 'inset';
  collapsible?: 'offcanvas' | 'icon' | 'none';
  containerClassName?: string;
  animateOnHover?: boolean;
  transition?: Transition;
};

function Sidebar({
  side = 'left',
  variant = 'sidebar',
  collapsible = 'icon',
  className,
  children,
  animateOnHover = true,
  containerClassName,
  transition = { type: 'spring', stiffness: 350, damping: 35 },
  ...props
}: SidebarProps) {
  const { isMobile, state, openMobile, setOpenMobile } = useSidebar();

  if (collapsible === 'none') {
    return (
      <Highlight
        enabled={animateOnHover}
        hover
        controlledItems
        mode="parent"
        containerClassName={containerClassName}
        transition={transition}
      >
        <div
          data-slot="sidebar"
          data-state={state}
          className={cn(
            'bg-sidebar text-sidebar-foreground flex h-full w-[var(--sidebar-width)] flex-col border-r border-sidebar-border',
            className
          )}
          {...props}
        >
          {children}
        </div>
      </Highlight>
    );
  }

  if (isMobile) {
    return (
      <Sheet open={openMobile} onOpenChange={setOpenMobile}>
        <SheetContent
          data-sidebar="sidebar"
          data-slot="sidebar"
          data-mobile="true"
          className="bg-[#09090B] text-zinc-100 w-[var(--sidebar-width-mobile)] max-w-[85vw] p-0 border-r border-zinc-800 focus:outline-none"
          side={side}
          showCloseButton={true}
        >
          <SheetHeader className="sr-only">
            <SheetTitle>Navigation Menu</SheetTitle>
            <SheetDescription>Platform navigation and status controls</SheetDescription>
          </SheetHeader>
          <Highlight
            enabled={animateOnHover}
            hover
            controlledItems
            mode="parent"
            containerClassName={cn('h-full flex flex-col', containerClassName)}
            transition={transition}
          >
            <div className="flex h-full w-full flex-col">{children}</div>
          </Highlight>
        </SheetContent>
      </Sheet>
    );
  }

  const isCollapsed = state === 'collapsed';

  return (
    <div
      className="group peer text-sidebar-foreground hidden lg:block"
      data-state={state}
      data-collapsible={isCollapsed ? collapsible : ''}
      data-variant={variant}
      data-side={side}
      data-slot="sidebar"
    >
      {/* Desktop Layout Gap reservation: animates width to smoothly push/pull main content */}
      <div
        data-slot="sidebar-gap"
        className={cn(
          'relative bg-transparent transition-[width] duration-300 ease-[cubic-bezier(0.7,-0.15,0.25,1.15)] select-none pointer-events-none',
          collapsible === 'offcanvas' && isCollapsed ? 'w-0' : '',
          collapsible === 'icon' && isCollapsed
            ? 'w-[var(--sidebar-width-icon)]'
            : !isCollapsed
            ? 'w-[var(--sidebar-width)]'
            : ''
        )}
      />

      {/* Fixed Sidebar Container */}
      <aside
        data-slot="sidebar-container"
        className={cn(
          'fixed inset-y-0 z-30 hidden h-screen bg-[#09090B] border-r border-zinc-800 transition-[left,right,width] duration-300 ease-[cubic-bezier(0.75,0,0.25,1)] lg:flex lg:flex-col overflow-hidden',
          side === 'left' ? 'left-0' : 'right-0',
          collapsible === 'offcanvas' && isCollapsed
            ? side === 'left'
              ? '-left-[var(--sidebar-width)]'
              : '-right-[var(--sidebar-width)]'
            : '',
          collapsible === 'icon' && isCollapsed
            ? 'w-[var(--sidebar-width-icon)]'
            : 'w-[var(--sidebar-width)]',
          className
        )}
        {...props}
      >
        <Highlight
          containerClassName={cn('h-full w-full flex flex-col', containerClassName)}
          enabled={animateOnHover}
          hover
          controlledItems
          mode="parent"
          forceUpdateBounds
          transition={transition}
        >
          <div
            data-sidebar="sidebar"
            data-slot="sidebar-inner"
            className="flex h-full w-full flex-col overflow-hidden"
          >
            {children}
          </div>
        </Highlight>
      </aside>
    </div>
  );
}

export type SidebarTriggerProps = React.ComponentProps<'button'>;

function SidebarTrigger({ className, onClick, ...props }: SidebarTriggerProps) {
  const { toggleSidebar } = useSidebar();

  return (
    <button
      type="button"
      data-sidebar="trigger"
      data-slot="sidebar-trigger"
      aria-label="Toggle Sidebar"
      className={cn(
        'inline-flex items-center justify-center p-2 rounded-lg text-zinc-400 hover:text-white hover:bg-zinc-800 transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-zinc-600',
        className
      )}
      onClick={(event) => {
        onClick?.(event);
        toggleSidebar();
      }}
      {...props}
    >
      <PanelLeft size={18} />
      <span className="sr-only">Toggle Sidebar</span>
    </button>
  );
}

export type SidebarRailProps = React.ComponentProps<'button'>;

function SidebarRail({ className, ...props }: SidebarRailProps) {
  const { toggleSidebar, state } = useSidebar();

  return (
    <button
      type="button"
      data-sidebar="rail"
      data-slot="sidebar-rail"
      aria-label="Toggle Sidebar"
      tabIndex={-1}
      onClick={toggleSidebar}
      title={state === 'collapsed' ? 'Expand Sidebar (Ctrl+B)' : 'Collapse Sidebar (Ctrl+B)'}
      className={cn(
        'absolute inset-y-0 right-0 z-40 hidden w-2 translate-x-1/2 cursor-w-resize transition-colors hover:bg-zinc-700/50 lg:block focus:outline-none group-data-[collapsible=icon]:cursor-e-resize',
        'after:absolute after:inset-y-0 after:left-1/2 after:w-[1px] hover:after:bg-zinc-500 after:transition-colors',
        className
      )}
      {...props}
    />
  );
}

export type SidebarInsetProps = React.ComponentProps<'main'>;

function SidebarInset({ className, ...props }: SidebarInsetProps) {
  return (
    <main
      data-slot="sidebar-inset"
      className={cn('relative flex min-w-0 flex-1 flex-col', className)}
      {...props}
    />
  );
}

export type SidebarHeaderProps = React.ComponentProps<'div'>;

function SidebarHeader({ className, ...props }: SidebarHeaderProps) {
  return (
    <div
      data-slot="sidebar-header"
      data-sidebar="header"
      className={cn('flex flex-col shrink-0', className)}
      {...props}
    />
  );
}

export type SidebarFooterProps = React.ComponentProps<'div'>;

function SidebarFooter({ className, ...props }: SidebarFooterProps) {
  return (
    <div
      data-slot="sidebar-footer"
      data-sidebar="footer"
      className={cn('mt-auto flex flex-col shrink-0', className)}
      {...props}
    />
  );
}

export type SidebarSeparatorProps = React.ComponentProps<'div'>;

function SidebarSeparator({ className, ...props }: SidebarSeparatorProps) {
  return (
    <div
      data-slot="sidebar-separator"
      data-sidebar="separator"
      className={cn('h-px w-full bg-zinc-800', className)}
      {...props}
    />
  );
}

export type SidebarContentProps = React.ComponentProps<'div'>;

function SidebarContent({ className, ...props }: SidebarContentProps) {
  return (
    <div
      data-slot="sidebar-content"
      data-sidebar="content"
      className={cn(
        'flex min-h-0 flex-1 flex-col gap-1 overflow-y-auto overflow-x-hidden p-2 group-data-[collapsible=icon]:p-1.5',
        className
      )}
      {...props}
    />
  );
}

export type SidebarGroupProps = React.ComponentProps<'div'>;

function SidebarGroup({ className, ...props }: SidebarGroupProps) {
  return (
    <div
      data-slot="sidebar-group"
      data-sidebar="group"
      className={cn('relative flex w-full min-w-0 flex-col py-1', className)}
      {...props}
    />
  );
}

export type SidebarGroupLabelProps = React.ComponentProps<'div'> & {
  asChild?: boolean;
};

function SidebarGroupLabel({
  className,
  asChild = false,
  ...props
}: SidebarGroupLabelProps) {
  const Comp = asChild ? Slot.Root : 'div';

  return (
    <Comp
      data-slot="sidebar-group-label"
      data-sidebar="group-label"
      className={cn(
        'flex h-7 shrink-0 items-center px-3 text-[10px] font-bold uppercase tracking-wider text-zinc-500 font-mono transition-opacity duration-200',
        'group-data-[collapsible=icon]:opacity-0 group-data-[collapsible=icon]:h-0 group-data-[collapsible=icon]:p-0 group-data-[collapsible=icon]:overflow-hidden',
        className
      )}
      {...props}
    />
  );
}

export type SidebarGroupContentProps = React.ComponentProps<'div'>;

function SidebarGroupContent({ className, ...props }: SidebarGroupContentProps) {
  return (
    <div
      data-slot="sidebar-group-content"
      data-sidebar="group-content"
      className={cn('w-full', className)}
      {...props}
    />
  );
}

export type SidebarMenuProps = React.ComponentProps<'ul'>;

function SidebarMenu({ className, ...props }: SidebarMenuProps) {
  return (
    <ul
      data-slot="sidebar-menu"
      data-sidebar="menu"
      className={cn('flex w-full min-w-0 flex-col gap-1 list-none p-0 m-0', className)}
      {...props}
    />
  );
}

export type SidebarMenuItemProps = React.ComponentProps<'li'>;

function SidebarMenuItem({ className, ...props }: SidebarMenuItemProps) {
  return (
    <li
      data-slot="sidebar-menu-item"
      data-sidebar="menu-item"
      className={cn('group/menu-item relative list-none', className)}
      {...props}
    />
  );
}

const sidebarMenuButtonVariants = cva(
  'peer/menu-button flex w-full items-center gap-3 overflow-hidden rounded-xl text-left text-xs font-medium outline-none transition-[padding,background-color,color] focus-visible:ring-2 focus-visible:ring-zinc-600 disabled:pointer-events-none disabled:opacity-50',
  {
    variants: {
      variant: {
        default: 'text-zinc-400 hover:text-zinc-100',
        outline: 'border border-zinc-800 bg-[#121214] hover:bg-zinc-800 text-zinc-300',
      },
      size: {
        default: 'h-10 px-3 py-2 group-data-[collapsible=icon]:h-9 group-data-[collapsible=icon]:w-9 group-data-[collapsible=icon]:p-0 group-data-[collapsible=icon]:justify-center group-data-[collapsible=icon]:mx-auto',
        sm: 'h-8 px-2 text-xs group-data-[collapsible=icon]:h-8 group-data-[collapsible=icon]:w-8 group-data-[collapsible=icon]:p-0 group-data-[collapsible=icon]:justify-center group-data-[collapsible=icon]:mx-auto',
        lg: 'h-12 px-3 text-sm group-data-[collapsible=icon]:h-10 group-data-[collapsible=icon]:w-10 group-data-[collapsible=icon]:p-0 group-data-[collapsible=icon]:justify-center group-data-[collapsible=icon]:mx-auto',
      },
    },
    defaultVariants: {
      variant: 'default',
      size: 'default',
    },
  }
);

export type SidebarMenuButtonProps = React.ComponentProps<'button'> & {
  asChild?: boolean;
  isActive?: boolean;
  tooltip?: string | React.ComponentProps<typeof TooltipContent>;
} & VariantProps<typeof sidebarMenuButtonVariants>;

function SidebarMenuButton({
  asChild = false,
  isActive = false,
  variant = 'default',
  size = 'default',
  tooltip,
  className,
  children,
  ...props
}: SidebarMenuButtonProps) {
  const Comp = asChild ? Slot.Root : 'button';
  const { isMobile, state } = useSidebar();
  const isCollapsed = state === 'collapsed' && !isMobile;

  const button = (
    <HighlightItem activeClassName="bg-zinc-800/80 rounded-xl">
      <Comp
        data-slot="sidebar-menu-button"
        data-sidebar="menu-button"
        data-size={size}
        data-active={isActive}
        className={cn(
          sidebarMenuButtonVariants({ variant, size }),
          isActive && 'bg-zinc-800 text-white border border-zinc-700 shadow-sm font-semibold',
          className
        )}
        {...props}
      >
        {children}
      </Comp>
    </HighlightItem>
  );

  if (!tooltip) {
    return button;
  }

  const tooltipProps = typeof tooltip === 'string' ? { children: tooltip } : tooltip;

  return (
    <Tooltip>
      <TooltipTrigger asChild>{button}</TooltipTrigger>
      {isCollapsed && (
        <TooltipContent side="right" align="center" {...tooltipProps} />
      )}
    </Tooltip>
  );
}

export type SidebarMenuBadgeProps = React.ComponentProps<'div'>;

function SidebarMenuBadge({ className, ...props }: SidebarMenuBadgeProps) {
  return (
    <div
      data-slot="sidebar-menu-badge"
      data-sidebar="menu-badge"
      className={cn(
        'pointer-events-none ml-auto flex items-center transition-opacity duration-200 group-data-[collapsible=icon]:hidden',
        className
      )}
      {...props}
    />
  );
}

export {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarInset,
  SidebarMenu,
  SidebarMenuBadge,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarProvider,
  SidebarRail,
  SidebarSeparator,
  SidebarTrigger,
  useSidebar,
};
