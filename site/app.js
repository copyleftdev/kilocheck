(() => {
  "use strict";

  const PHASES = Object.freeze([
    Object.freeze({ id: "ingest", code: "01 / INGEST", title: "Acquire the artifact", detail: "Pull a versioned Kilo Data release with its manifest and published hash." }),
    Object.freeze({ id: "normalize", code: "02 / NORMALIZE", title: "Make evidence typed", detail: "Resolve source shapes into explicit observations without erasing provenance." }),
    Object.freeze({ id: "compile", code: "03 / COMPILE", title: "Freeze the snapshot", detail: "Build one immutable index designed for deterministic, memory-mapped lookup." }),
    Object.freeze({ id: "check", code: "04 / CHECK", title: "Observe without calling out", detail: "Query bounded local evidence. Return stable JSON and a distinct operational state." })
  ]);

  const revealItems = document.querySelectorAll(".reveal");
  if ("IntersectionObserver" in window && !matchMedia("(prefers-reduced-motion: reduce)").matches) {
    const revealObserver = new IntersectionObserver((entries, observer) => {
      for (const entry of entries) {
        if (entry.isIntersecting) {
          entry.target.classList.add("is-visible");
          observer.unobserve(entry.target);
        }
      }
    }, { rootMargin: "0px 0px -8%", threshold: 0.08 });
    for (const item of revealItems) revealObserver.observe(item);
  } else {
    for (const item of revealItems) item.classList.add("is-visible");
  }

  const copyButton = document.querySelector("#copy-command");
  copyButton?.addEventListener("click", async () => {
    const original = copyButton.innerHTML;
    try {
      await navigator.clipboard.writeText(copyButton.dataset.copy);
      copyButton.textContent = "COPIED TO BUFFER";
    } catch {
      copyButton.textContent = copyButton.dataset.copy;
    }
    window.setTimeout(() => { copyButton.innerHTML = original; }, 1600);
  });

  class SignalArena {
    static CAPACITY = 48;

    constructor(canvas, machine) {
      this.canvas = canvas;
      this.machine = machine;
      this.context = canvas.getContext("2d", { alpha: true, desynchronized: true });
      this.capacity = SignalArena.CAPACITY;
      this.x = new Float32Array(this.capacity);
      this.y = new Float32Array(this.capacity);
      this.progress = new Float32Array(this.capacity);
      this.speed = new Float32Array(this.capacity);
      this.lane = new Int8Array(this.capacity);
      this.active = new Uint8Array(this.capacity);
      this.nodeX = new Float32Array(PHASES.length);
      this.nodeY = new Float32Array(PHASES.length);
      this.cursor = 0;
      this.activeCount = 0;
      this.phase = 0;
      this.phaseElapsed = 0;
      this.spawnElapsed = 0;
      this.lastTime = 0;
      this.raf = 0;
      this.width = 0;
      this.height = 0;
      this.visible = true;
      this.manualPause = false;
      this.reducedMotion = matchMedia("(prefers-reduced-motion: reduce)").matches;
      this.colors = Object.freeze(["#b6f232", "#f0bd36", "#e84a37"]);
      this.boundFrame = this.frame.bind(this);
      this.resizeObserver = new ResizeObserver(() => this.resize());
      this.visibilityObserver = new IntersectionObserver((entries) => {
        this.visible = entries[0]?.isIntersecting ?? false;
        this.reconcile();
      }, { threshold: 0.01 });
      this.resizeObserver.observe(canvas);
      this.visibilityObserver.observe(canvas);
      document.addEventListener("visibilitychange", () => this.reconcile());
      this.resize();
      this.seed();
      this.setPhase(0);
      this.reconcile();
    }

    resize() {
      const rect = this.canvas.getBoundingClientRect();
      const ratio = Math.min(window.devicePixelRatio || 1, 2);
      const width = Math.max(1, Math.round(rect.width * ratio));
      const height = Math.max(1, Math.round(rect.height * ratio));
      if (width === this.canvas.width && height === this.canvas.height) return;
      this.canvas.width = width;
      this.canvas.height = height;
      this.width = width;
      this.height = height;
      this.context.setTransform(ratio, 0, 0, ratio, 0, 0);
      this.cssWidth = rect.width;
      this.cssHeight = rect.height;
      for (let index = 0; index < PHASES.length; index += 1) {
        this.nodeX[index] = rect.width * (0.12 + index * 0.255);
        this.nodeY[index] = rect.height * (index % 2 === 0 ? 0.48 : 0.58);
      }
      if (this.reducedMotion || this.manualPause) this.draw();
    }

    seed() {
      for (let index = 0; index < 18; index += 1) {
        this.spawn(index / 18);
      }
    }

    spawn(initialProgress = 0) {
      const index = this.cursor;
      if (this.active[index] === 0) this.activeCount += 1;
      this.active[index] = 1;
      this.progress[index] = initialProgress;
      this.speed[index] = 0.055 + (index % 7) * 0.006;
      this.lane[index] = (index % 5) - 2;
      this.cursor = (this.cursor + 1) % this.capacity;
    }

    setPhase(index) {
      this.phase = index;
      const phase = PHASES[index];
      this.machine.dataset.machineState = phase.id;
      document.querySelector("#phase-code").textContent = phase.code;
      document.querySelector("#phase-title").textContent = phase.title;
      document.querySelector("#phase-detail").textContent = phase.detail;
    }

    setPaused(paused) {
      this.manualPause = paused;
      this.reconcile();
    }

    reconcile() {
      const shouldRun = !this.reducedMotion && !this.manualPause && this.visible && !document.hidden;
      if (shouldRun && this.raf === 0) {
        this.lastTime = performance.now();
        this.raf = requestAnimationFrame(this.boundFrame);
      } else if (!shouldRun && this.raf !== 0) {
        cancelAnimationFrame(this.raf);
        this.raf = 0;
      }
      if (!shouldRun) this.draw();
    }

    frame(now) {
      this.raf = 0;
      const elapsed = Math.min(50, now - this.lastTime);
      this.lastTime = now;
      this.phaseElapsed += elapsed;
      this.spawnElapsed += elapsed;

      if (this.phaseElapsed >= 2300) {
        this.phaseElapsed %= 2300;
        this.setPhase((this.phase + 1) % PHASES.length);
      }
      if (this.spawnElapsed >= 150) {
        this.spawnElapsed %= 150;
        this.spawn();
      }

      const seconds = elapsed / 1000;
      for (let index = 0; index < this.capacity; index += 1) {
        if (this.active[index] === 0) continue;
        this.progress[index] += this.speed[index] * seconds;
        if (this.progress[index] > 1) this.progress[index] -= 1;
      }
      this.draw();
      this.reconcile();
    }

    draw() {
      const context = this.context;
      const width = this.cssWidth || 1;
      const height = this.cssHeight || 1;
      context.clearRect(0, 0, width, height);
      context.lineWidth = 1;
      context.strokeStyle = "rgba(113, 142, 91, 0.26)";
      context.setLineDash([3, 7]);
      context.beginPath();
      for (let index = 0; index < PHASES.length - 1; index += 1) {
        context.moveTo(this.nodeX[index], this.nodeY[index]);
        context.lineTo(this.nodeX[index + 1], this.nodeY[index + 1]);
      }
      context.stroke();
      context.setLineDash([]);

      for (let index = 0; index < PHASES.length; index += 1) {
        const selected = index === this.phase;
        context.strokeStyle = selected ? this.colors[0] : "rgba(130, 151, 112, 0.38)";
        context.fillStyle = selected ? "rgba(182, 242, 50, 0.10)" : "rgba(11, 15, 10, 0.8)";
        context.lineWidth = selected ? 2 : 1;
        context.beginPath();
        context.rect(this.nodeX[index] - 17, this.nodeY[index] - 17, 34, 34);
        context.fill();
        context.stroke();
      }

      for (let index = 0; index < this.capacity; index += 1) {
        if (this.active[index] === 0) continue;
        const scaled = this.progress[index] * (PHASES.length - 1);
        const segment = Math.min(PHASES.length - 2, Math.floor(scaled));
        const local = scaled - segment;
        const x = this.nodeX[segment] + (this.nodeX[segment + 1] - this.nodeX[segment]) * local;
        const y = this.nodeY[segment] + (this.nodeY[segment + 1] - this.nodeY[segment]) * local + this.lane[index] * 4;
        context.globalAlpha = 0.28 + (index % 5) * 0.12;
        context.fillStyle = this.colors[index % this.colors.length];
        context.fillRect(Math.round(x), Math.round(y), index % 4 === 0 ? 5 : 2, 2);
      }
      context.globalAlpha = 1;
    }
  }

  const canvas = document.querySelector("#signal-canvas");
  const machine = document.querySelector(".machine");
  const toggle = document.querySelector("#machine-toggle");
  const mode = document.querySelector("#machine-mode");
  if (canvas && machine && toggle && mode) {
    const arena = new SignalArena(canvas, machine);
    toggle.addEventListener("click", () => {
      const paused = toggle.getAttribute("aria-pressed") !== "true";
      toggle.setAttribute("aria-pressed", String(paused));
      toggle.textContent = paused ? "RESUME" : "PAUSE";
      mode.textContent = paused ? "PAUSED" : "RUNNING";
      arena.setPaused(paused);
    });
    window.__KILO_ARENA__ = Object.freeze({
      capacity: arena.capacity,
      get active() { return arena.activeCount; },
      get scheduledFrames() { return arena.raf === 0 ? 0 : 1; }
    });
  }
})();
