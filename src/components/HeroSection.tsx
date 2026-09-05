import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { ArrowUpRight, X, Sun, Moon } from 'lucide-react';

const easeCustom = [0.22, 1, 0.36, 1] as const;

export default function HeroSection() {
  const [menuOpen, setMenuOpen] = useState(false);
  const [isDark, setIsDark] = useState(true);

  useEffect(() => {
    const checkDark = () => {
      const isHtmlDark = document.documentElement.classList.contains('dark') ||
        document.documentElement.getAttribute('data-theme') === 'dark';
      setIsDark(isHtmlDark);
    };

    checkDark();

    const handleThemeChange = () => checkDark();
    window.addEventListener('themechange', handleThemeChange);
    window.addEventListener('storage', handleThemeChange);

    return () => {
      window.removeEventListener('themechange', handleThemeChange);
      window.removeEventListener('storage', handleThemeChange);
    };
  }, []);

  const toggleTheme = () => {
    const nextDark = !isDark;
    setIsDark(nextDark);
    if (nextDark) {
      document.documentElement.classList.add('dark');
      document.documentElement.setAttribute('data-theme', 'dark');
      try { localStorage.setItem('qt-theme', 'dark'); } catch (_) {}
    } else {
      document.documentElement.classList.remove('dark');
      document.documentElement.setAttribute('data-theme', 'light');
      try { localStorage.setItem('qt-theme', 'light'); } catch (_) {}
    }
    window.dispatchEvent(new Event('themechange'));
  };

  // Top nav fade down
  const fadeDown = {
    initial: { opacity: 0, y: -16 },
    animate: (i: number) => ({
      opacity: 1,
      y: 0,
      transition: {
        delay: i * 0.1,
        duration: 0.55,
        ease: easeCustom,
      },
    }),
  };

  // Content fade up
  const fadeUp = {
    initial: { opacity: 0, y: 20 },
    animate: (i: number) => ({
      opacity: 1,
      y: 0,
      transition: {
        delay: i * 0.1,
        duration: 0.6,
        ease: easeCustom,
      },
    }),
  };

  return (
    <div
      className="relative w-full h-screen min-h-[640px] flex flex-col justify-between overflow-hidden bg-[#ffffff] dark:bg-[#121214] text-neutral-900 dark:text-white select-none transition-colors duration-300"
      style={{ fontFamily: "'Inter', sans-serif" }}
    >
      {/* BACKGROUND 3D VIDEO: Shifted to left-center and scaled slightly smaller */}
      <div className="absolute inset-0 w-full h-full overflow-hidden pointer-events-none z-0">
        <video
          autoPlay
          loop
          muted
          playsInline
          className="absolute w-[95%] h-[95%] max-w-none top-[2.5%] left-[-15%] md:left-[-10%] lg:left-[-5%] object-cover pointer-events-none transition-all duration-700"
          style={{
            filter: isDark
              ? 'brightness(0.85) contrast(1.1) saturate(1.05)'
              : 'brightness(1.04) contrast(1.02) saturate(1.05)',
          }}
          src="https://d8j0ntlcm91z4.cloudfront.net/user_38xzZboKViGWJOttwIXH07lWA1P/hf_20260517_222138_3e3205be-3364-417b-a64a-bfe087acbec4.mp4"
        />
        {/* Vignette and Dark Theme Overlay only in dark mode */}
        {isDark && (
          <>
            <div className="absolute inset-0 bg-gradient-to-r from-black/50 via-transparent to-black/60 pointer-events-none" />
            <div className="absolute inset-0 bg-gradient-to-b from-black/40 via-transparent to-black/60 pointer-events-none" />
          </>
        )}
      </div>

      {/* 1. TOP BAR */}
      <header className="relative z-20 w-full px-6 sm:px-10 md:px-14 pt-6 md:pt-8 flex items-center justify-between">
        {/* Left: Favicon Logo + Project Name */}
        <motion.a
          href="/"
          custom={0}
          variants={fadeDown}
          initial="initial"
          animate="animate"
          className="flex items-center gap-3.5 cursor-pointer no-underline text-black dark:text-white group"
          aria-label="Quantum Trust Home"
        >
          <div className="w-10 h-10 rounded-xl bg-black dark:bg-white flex items-center justify-center p-1.5 shadow-md group-hover:scale-105 transition-transform border border-black/10 dark:border-white/10">
            <img
              src="/favicon.svg"
              alt="Quantum Trust Logo"
              className="w-full h-full object-contain filter dark:invert-0"
            />
          </div>
          <span className="text-base sm:text-lg md:text-xl font-extrabold tracking-[0.22em] uppercase text-black dark:text-white transition-colors duration-200">
            Quantum Trust
          </span>
        </motion.a>

        {/* Right: Dark Mode Toggle Icon + Round Hamburger Button */}
        <div className="flex items-center gap-3.5">
          {/* Sun/Theme Toggle Button */}
          <motion.button
            custom={1}
            variants={fadeDown}
            initial="initial"
            animate="animate"
            onClick={toggleTheme}
            className="w-11 h-11 rounded-full bg-white/90 dark:bg-[#18181b]/90 backdrop-blur-md border border-black/10 dark:border-white/15 text-neutral-800 dark:text-amber-400 flex items-center justify-center cursor-pointer transition-all duration-300 hover:scale-105 active:scale-95 shadow-md focus:outline-none"
            aria-label={isDark ? 'Switch to light mode' : 'Switch to dark mode'}
            title={isDark ? 'Switch to light mode' : 'Switch to dark mode'}
          >
            <AnimatePresence mode="wait" initial={false}>
              {isDark ? (
                <motion.div
                  key="sun-icon"
                  initial={{ rotate: -90, scale: 0, opacity: 0 }}
                  animate={{ rotate: 0, scale: 1, opacity: 1 }}
                  exit={{ rotate: 90, scale: 0, opacity: 0 }}
                  transition={{ duration: 0.2, ease: 'easeOut' }}
                >
                  <Sun className="w-5 h-5 text-amber-400 stroke-[2.2]" />
                </motion.div>
              ) : (
                <motion.div
                  key="moon-icon"
                  initial={{ rotate: 90, scale: 0, opacity: 0 }}
                  animate={{ rotate: 0, scale: 1, opacity: 1 }}
                  exit={{ rotate: -90, scale: 0, opacity: 0 }}
                  transition={{ duration: 0.2, ease: 'easeOut' }}
                >
                  <Moon className="w-5 h-5 text-neutral-800 stroke-[2.2]" />
                </motion.div>
              )}
            </AnimatePresence>
          </motion.button>

          {/* Hamburger Menu Button */}
          <motion.button
            custom={1.1}
            variants={fadeDown}
            initial="initial"
            animate="animate"
            onClick={() => setMenuOpen(true)}
            className="w-11 h-11 rounded-full bg-black dark:bg-white text-white dark:text-black flex flex-col items-center justify-center gap-1 cursor-pointer transition-transform hover:scale-105 active:scale-95 focus:outline-none shadow-lg"
            aria-label="Open Navigation Menu"
          >
            <span className="w-4 h-[2px] bg-white dark:bg-black rounded-full" />
            <span className="w-4 h-[2px] bg-white dark:bg-black rounded-full" />
            <span className="w-4 h-[2px] bg-white dark:bg-black rounded-full" />
          </motion.button>
        </div>
      </header>

      {/* 2. MAIN BODY SECTION: 2-COLUMN VIEWPORT LAYOUT */}
      <main className="relative z-10 w-full flex-1 px-6 sm:px-10 md:px-14 grid grid-cols-1 lg:grid-cols-12 items-center min-h-0 py-2">
        {/* Left Column: Descriptive info blocks positioned around the 3D star */}
        <div className="lg:col-span-5 h-full flex flex-col justify-between py-6 md:py-10 pointer-events-none">
          {/* Middle-Left: Quantum-Inspired Digital Signature */}
          <motion.div
            custom={2}
            variants={fadeUp}
            initial="initial"
            animate="animate"
            className="my-auto max-w-[240px] pt-4"
          >
            <p className="text-[12px] sm:text-[13px] md:text-[14px] font-bold tracking-[0.16em] uppercase text-black dark:text-white leading-[1.35] drop-shadow-sm">
              QUANTUM-INSPIRED<br />
              DIGITAL SIGNATURE<br />
              SECURITY &<br />
              VERIFICATION
            </p>
          </motion.div>

          {/* Bottom-Left: Real Cryptographic Integrity Analysis */}
          <motion.div
            custom={3}
            variants={fadeUp}
            initial="initial"
            animate="animate"
            className="mt-auto max-w-[320px] text-left sm:text-right sm:self-start lg:self-end pb-2"
          >
            <p className="text-[11px] sm:text-[12px] md:text-[12.5px] font-bold tracking-[0.16em] uppercase text-black dark:text-white leading-[1.45] drop-shadow-sm">
              REAL CRYPTOGRAPHIC INTEGRITY<br />
              ANALYSIS, TAMPER DETECTION &<br />
              ZERO-KNOWLEDGE DOCUMENT<br />
              SECURITY
            </p>
          </motion.div>
        </div>

        {/* Right Column: Hero Headline, Subtitles, and Centered CTA Button */}
        <div className="lg:col-span-7 flex flex-col items-center text-center justify-center gap-3 sm:gap-4 md:gap-5 py-4 lg:pl-10">
          {/* Eyebrow / Top Subtitle */}
          <motion.div
            custom={2}
            variants={fadeUp}
            initial="initial"
            animate="animate"
          >
            <p className="text-xs sm:text-sm md:text-[14px] font-bold tracking-[0.28em] uppercase text-black dark:text-white leading-relaxed drop-shadow-sm">
              SECURE TODAY.<br />
              TRUST TOMORROW.
            </p>
          </motion.div>

          {/* Stacked Giant Headline: QUANTUM TRUST */}
          <div className="flex flex-col items-center select-none my-1">
            <div className="overflow-hidden leading-[0.86]">
              <motion.h1
                initial={{ y: '115%' }}
                animate={{ y: 0 }}
                transition={{
                  delay: 0.25,
                  duration: 0.75,
                  ease: easeCustom,
                }}
                className="font-[900] uppercase text-black dark:text-white tracking-[-0.03em] m-0 p-0 block drop-shadow-sm"
                style={{
                  fontSize: 'clamp(3.8rem, 8.2vw, 7.8rem)',
                  lineHeight: 0.86,
                }}
              >
                QUANTUM
              </motion.h1>
            </div>
            <div className="overflow-hidden leading-[0.86]">
              <motion.h1
                initial={{ y: '115%' }}
                animate={{ y: 0 }}
                transition={{
                  delay: 0.38,
                  duration: 0.75,
                  ease: easeCustom,
                }}
                className="font-[900] uppercase text-black dark:text-white tracking-[-0.03em] m-0 p-0 block drop-shadow-sm"
                style={{
                  fontSize: 'clamp(3.8rem, 8.2vw, 7.8rem)',
                  lineHeight: 0.86,
                }}
              >
                TRUST
              </motion.h1>
            </div>
          </div>

          {/* Under-Headline Tagline */}
          <motion.div
            custom={4}
            variants={fadeUp}
            initial="initial"
            animate="animate"
          >
            <p className="text-xs sm:text-sm md:text-[14px] font-bold tracking-[0.26em] uppercase text-black dark:text-white leading-relaxed drop-shadow-sm">
              NEXT-GEN DIGITAL SIGNATURE<br />
              SECURITY & VERIFICATION
            </p>
          </motion.div>

          {/* Glowing CTA Button: GET STARTED ↗ */}
          <motion.div
            custom={5}
            variants={fadeUp}
            initial="initial"
            animate="animate"
            className="pt-2 sm:pt-4"
          >
            <a
              href="/dashboard"
              className="inline-flex items-center justify-center gap-2.5 px-8 sm:px-10 py-3.5 sm:py-4 rounded-full bg-black text-white hover:bg-neutral-800 dark:bg-[#141416] dark:text-[#c084fc] font-bold text-sm sm:text-base tracking-[0.22em] uppercase border border-black/20 dark:border-[#a855f7]/30 shadow-[0_4px_20px_rgba(0,0,0,0.15)] hover:shadow-[0_6px_25px_rgba(0,0,0,0.25)] dark:shadow-[0_0_25px_rgba(168,85,247,0.32)] dark:hover:shadow-[0_0_40px_rgba(168,85,247,0.55)] hover:scale-[1.03] active:scale-[0.98] transition-all duration-300 no-underline"
              title="Get Started — Go to Dashboard"
            >
              <span>GET STARTED</span>
              <ArrowUpRight className="w-5 h-5 stroke-[2.5]" />
            </a>
          </motion.div>
        </div>
      </main>

      {/* Bottom Padding Spacer */}
      <div className="relative z-10 w-full pb-4 sm:pb-6 pointer-events-none" />

      {/* QUICK MENU OVERLAY */}
      <AnimatePresence>
        {menuOpen && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.25, ease: easeCustom }}
            className="fixed inset-0 z-50 bg-[#0c0c0e]/95 backdrop-blur-xl text-white flex flex-col justify-between px-6 sm:px-10 py-8 transition-colors duration-200"
          >
            {/* Top row */}
            <div className="flex items-center justify-between">
              <a
                href="/"
                className="flex items-center gap-3.5 cursor-pointer no-underline text-white"
                onClick={() => setMenuOpen(false)}
                aria-label="Quantum Trust Home"
              >
                <div className="w-10 h-10 rounded-xl bg-black flex items-center justify-center p-1.5 shadow-md border border-white/10">
                  <img
                    src="/favicon.svg"
                    alt="Quantum Trust Logo"
                    className="w-full h-full object-contain"
                  />
                </div>
                <span className="text-xl font-bold tracking-[0.22em] uppercase text-white">
                  Quantum Trust
                </span>
              </a>

              <div className="flex items-center gap-3">
                {/* Theme Toggle inside Menu */}
                <button
                  onClick={toggleTheme}
                  className="w-11 h-11 rounded-full bg-neutral-800 border border-white/15 text-amber-400 flex items-center justify-center cursor-pointer transition-transform hover:scale-105"
                  aria-label={isDark ? 'Switch to light mode' : 'Switch to dark mode'}
                >
                  {isDark ? (
                    <Sun className="w-5 h-5 text-amber-400 stroke-[2.2]" />
                  ) : (
                    <Moon className="w-5 h-5 text-white stroke-[2.2]" />
                  )}
                </button>

                {/* Close Button */}
                <button
                  onClick={() => setMenuOpen(false)}
                  className="w-11 h-11 rounded-full bg-white text-black flex items-center justify-center cursor-pointer focus:outline-none transition-transform hover:scale-105"
                  aria-label="Close Navigation Menu"
                >
                  <X className="w-5 h-5 stroke-[2.5]" />
                </button>
              </div>
            </div>

            {/* Links in modal */}
            <div className="flex flex-col gap-8 mt-16 max-w-lg mx-auto w-full text-center sm:text-left">
              <a
                href="/verify"
                onClick={() => setMenuOpen(false)}
                className="text-2xl sm:text-3xl font-bold tracking-widest uppercase text-white hover:text-[#c084fc] transition-colors"
              >
                Verify Document
              </a>
              <a
                href="/dashboard"
                onClick={() => setMenuOpen(false)}
                className="text-2xl sm:text-3xl font-bold tracking-widest uppercase text-white hover:text-[#c084fc] transition-colors"
              >
                Dashboard
              </a>
              <a
                href="/security"
                onClick={() => setMenuOpen(false)}
                className="text-2xl sm:text-3xl font-bold tracking-widest uppercase text-white hover:text-[#c084fc] transition-colors"
              >
                Security Specs
              </a>
              <a
                href="/analysis"
                onClick={() => setMenuOpen(false)}
                className="text-2xl sm:text-3xl font-bold tracking-widest uppercase text-white hover:text-[#c084fc] transition-colors"
              >
                Analysis History
              </a>
            </div>

            {/* Bottom CTA */}
            <div className="mt-auto pb-6 flex items-center justify-between border-t border-white/10 pt-6">
              <a
                href="/dashboard"
                onClick={() => setMenuOpen(false)}
                className="inline-flex items-center gap-2 text-lg font-bold text-[#c084fc] tracking-widest uppercase hover:opacity-80 transition-opacity"
              >
                <span>Get Started</span>
                <ArrowUpRight className="w-5 h-5" />
              </a>
              <span className="text-xs font-mono text-neutral-400 uppercase tracking-wider">
                Quantum Trust Security Suite
              </span>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}


