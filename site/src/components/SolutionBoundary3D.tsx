import { For, onCleanup, onMount } from "solid-js";
import * as THREE from "three";
import { CSS2DObject, CSS2DRenderer } from "three/addons/renderers/CSS2DRenderer.js";
import type { BoundaryIcon } from "../data/solutions.ts";
import {
  createSceneResources,
  createTrace,
  palette,
  type SceneResources,
} from "./auth-flow/scene-primitives.ts";

type BoundaryStep = readonly [string, string, string, BoundaryIcon];

interface SolutionBoundary3DProps {
  sector: string;
  steps: BoundaryStep[];
}

const stationPositions: ReadonlyArray<readonly [number, number]> = [
  [-3.3, 1.05],
  [-1.1, -1.2],
  [1.1, 1.05],
  [3.3, -1.2],
];

/** Height above the board where each station's title label sits. */
const labelHeights: Record<BoundaryIcon, number> = {
  passkey: 1.52,
  key: 0.98,
  app: 1.88,
  rustyauth: 1.95,
  database: 1.22,
  policy: 1.02,
};

function addStepLabel(
  parent: THREE.Object3D,
  number: string,
  title: string,
  height: number,
  variant: "" | "accent" | "flow" = "",
) {
  const element = document.createElement("span");
  element.className = variant ? `boundary-step-label boundary-step-label--${variant}` : "boundary-step-label";
  if (number) {
    const index = document.createElement("i");
    index.textContent = number;
    element.append(index);
  }
  element.append(document.createTextNode(title));
  const label = new CSS2DObject(element);
  label.position.set(0, height, 0);
  parent.add(label);
  return label;
}

function buildStation(resources: SceneResources, icon: BoundaryIcon): THREE.Group {
  const { mesh: draw, plate } = resources;
  const group = new THREE.Group();

  if (icon !== "rustyauth") {
    group.add(plate(1.9, 1.65, 0.07, palette.white, 0.18));
  }

  if (icon === "passkey") {
    const stand = draw(new THREE.BoxGeometry(0.13, 0.42, 0.11), palette.ink);
    stand.position.set(0, 0.21, 0.05);
    group.add(stand);
    const screen = draw(new THREE.BoxGeometry(1.18, 0.78, 0.08), palette.white);
    screen.position.set(0, 0.82, 0.06);
    group.add(screen);
    const screenBar = draw(new THREE.BoxGeometry(0.95, 0.1, 0.04), palette.copper);
    screenBar.position.set(0, 1.01, 0.11);
    group.add(screenBar);
    const ring = draw(new THREE.TorusGeometry(0.17, 0.045, 12, 32), palette.ink);
    ring.position.set(-0.21, 0.76, 0.12);
    group.add(ring);
    const stem = draw(new THREE.BoxGeometry(0.34, 0.06, 0.05), palette.ink);
    stem.position.set(0.02, 0.64, 0.12);
    stem.rotation.z = -0.5;
    group.add(stem);
  } else if (icon === "key") {
    const body = draw(new THREE.BoxGeometry(0.92, 0.14, 0.4), palette.white);
    body.position.set(-0.1, 0.14, 0);
    group.add(body);
    const connector = draw(new THREE.BoxGeometry(0.3, 0.1, 0.24), palette.copper);
    connector.position.set(0.5, 0.13, 0);
    group.add(connector);
    const ring = draw(new THREE.TorusGeometry(0.16, 0.05, 12, 32), palette.ink);
    ring.rotation.x = Math.PI / 2;
    ring.position.set(-0.68, 0.14, 0);
    group.add(ring);
    const touchPad = draw(new THREE.CylinderGeometry(0.09, 0.09, 0.06, 24), palette.ink);
    touchPad.position.set(-0.16, 0.23, 0);
    group.add(touchPad);
  } else if (icon === "app") {
    const stand = draw(new THREE.BoxGeometry(0.13, 0.42, 0.11), palette.ink);
    stand.position.set(0, 0.21, 0.05);
    group.add(stand);
    const screen = draw(new THREE.BoxGeometry(1.34, 0.9, 0.08), palette.white);
    screen.position.set(0, 0.88, 0.06);
    group.add(screen);
    const screenBar = draw(new THREE.BoxGeometry(1.1, 0.1, 0.04), palette.copper);
    screenBar.position.set(0, 1.12, 0.11);
    group.add(screenBar);
    const chipData: Array<[number, number, number]> = [[-0.28, 0.84, 0.44], [0.3, 0.84, 0.5], [
      -0.22,
      0.6,
      0.56,
    ]];
    chipData.forEach(([x, y, width]) => {
      const chip = draw(new THREE.BoxGeometry(width, 0.14, 0.03), palette.paperDeep);
      chip.position.set(x, y, 0.11);
      group.add(chip);
    });
  } else if (icon === "database") {
    for (let layer = 0; layer < 3; layer += 1) {
      const disc = draw(
        new THREE.CylinderGeometry(0.46, 0.46, 0.2, 36),
        layer === 1 ? palette.paperDeep : palette.white,
      );
      disc.position.y = 0.17 + layer * 0.24;
      group.add(disc);
    }
    const cap = draw(new THREE.CylinderGeometry(0.46, 0.46, 0.08, 36), palette.ink);
    cap.position.y = 0.82;
    group.add(cap);
  } else if (icon === "policy") {
    const card = plate(1.08, 0.86, 0.07, palette.white, 0.09);
    card.position.y = 0.07;
    group.add(card);
    [[-0.4, -0.16, 0.62], [-0.4, 0.04, 0.44], [-0.4, 0.24, 0.7]].forEach(([x, z, width], row) => {
      const bar = draw(
        new THREE.BoxGeometry(width, 0.04, 0.07),
        row === 0 ? palette.ink : palette.paperDeep,
      );
      bar.position.set(x + width / 2, 0.18, z);
      group.add(bar);
    });
    const seal = draw(new THREE.CylinderGeometry(0.17, 0.17, 0.08, 32), palette.copper);
    seal.position.set(0.33, 0.18, -0.16);
    group.add(seal);
  }

  return group;
}

export default function SolutionBoundary3D(props: SolutionBoundary3DProps) {
  let host!: HTMLDivElement;
  const rustyIndex = Math.max(props.steps.findIndex(([, , , icon]) => icon === "rustyauth"), 0);

  onMount(() => {
    const reducedMotion = globalThis.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const canvas = document.createElement("canvas");
    host.append(canvas);

    const renderer = new THREE.WebGLRenderer({ canvas, alpha: true, antialias: true });
    renderer.setPixelRatio(Math.min(globalThis.devicePixelRatio, 2));
    renderer.outputColorSpace = THREE.SRGBColorSpace;

    const labels = new CSS2DRenderer();
    labels.domElement.className = "boundary-scene-labels";
    host.append(labels.domElement);

    const scene = new THREE.Scene();
    const camera = new THREE.OrthographicCamera(-1, 1, 1, -1, 0.1, 100);
    camera.position.set(7.2, 7.5, 7.2);
    camera.lookAt(0, 0.3, 0);

    const world = new THREE.Group();
    const baseYaw = -0.14;
    world.rotation.y = baseYaw;
    scene.add(world);

    const resources = createSceneResources();
    const { material: fill, mesh: draw, plate, trackGeometry, trackMaterial } = resources;

    const board = plate(9.6, 5.9, 0.14, palette.white, 0.42);
    board.position.y = -0.16;
    world.add(board);

    const gridPoints: THREE.Vector3[] = [];
    for (let x = -4.35; x <= 4.35; x += 0.7) {
      gridPoints.push(new THREE.Vector3(x, 0.005, -2.6), new THREE.Vector3(x, 0.005, 2.6));
    }
    for (let z = -2.6; z <= 2.6; z += 0.7) {
      gridPoints.push(new THREE.Vector3(-4.35, 0.005, z), new THREE.Vector3(4.35, 0.005, z));
    }
    const gridGeometry = trackGeometry(new THREE.BufferGeometry().setFromPoints(gridPoints));
    const gridMaterial = trackMaterial(
      new THREE.LineBasicMaterial({ color: palette.ink, transparent: true, opacity: 0.065 }),
    );
    world.add(new THREE.LineSegments(gridGeometry, gridMaterial));

    const stations: Array<{ group: THREE.Group; settled: number }> = [];
    const rustyLayers: Array<{ group: THREE.Group; settled: number; phase: number }> = [];
    let tokenDisc: THREE.Mesh | undefined;

    props.steps.slice(0, 4).forEach(([number, title, , icon], index) => {
      const [x, z] = stationPositions[index];
      const group = new THREE.Group();
      group.position.set(x, 0, z);
      world.add(group);
      stations.push({ group, settled: 0 });

      if (icon === "rustyauth") {
        // The boundary itself gets the homepage hero's layered-stack treatment.
        const layerSpecs: Array<{ size: number; height: number; color: number; settled: number }> = [
          { size: 1.55, height: 0.18, color: palette.ink, settled: 0 },
          { size: 1.2, height: 0.12, color: palette.white, settled: 0.5 },
          { size: 0.86, height: 0.13, color: palette.copper, settled: 1.0 },
        ];
        layerSpecs.forEach((spec, layerIndex) => {
          const layer = new THREE.Group();
          layer.position.y = spec.settled;
          layer.add(plate(spec.size, spec.size, spec.height, spec.color, 0.16));
          group.add(layer);
          rustyLayers.push({ group: layer, settled: spec.settled, phase: layerIndex * 1.4 });
        });
        const ring = draw(new THREE.TorusGeometry(0.44, 0.06, 12, 40), palette.ink);
        ring.rotation.x = Math.PI / 2;
        ring.position.y = 0.18;
        rustyLayers[1].group.add(ring);
        tokenDisc = draw(new THREE.CylinderGeometry(0.2, 0.2, 0.1, 32), palette.white);
        tokenDisc.position.y = 0.32;
        rustyLayers[2].group.add(tokenDisc);
      } else {
        group.add(buildStation(resources, icon));
      }

      addStepLabel(group, number, title, labelHeights[icon], icon === "rustyauth" ? "accent" : "");
    });

    const traces = stationPositions.slice(0, -1).map(([fromX, fromZ], index) => {
      const [toX, toZ] = stationPositions[index + 1];
      const edge = fromZ > toZ ? 1 : -1;
      return createTrace([
        [fromX + 1.05, fromZ],
        [toX, fromZ],
        [toX, toZ + edge * 1.0],
      ]);
    });
    const traceMaterial = trackMaterial(
      new THREE.LineBasicMaterial({ color: palette.ink, transparent: true, opacity: 0.48 }),
    );
    traces.forEach((path) => {
      const points = path.getPoints(60);
      const geometry = new THREE.BufferGeometry().setFromPoints(points);
      trackGeometry(geometry);
      world.add(new THREE.Line(geometry, traceMaterial));
      for (const endpoint of [points[0], points.at(-1)!]) {
        const node = draw(new THREE.SphereGeometry(0.045, 12, 12), palette.white);
        node.position.copy(endpoint);
        world.add(node);
      }
    });

    // Annotate what actually moves across the boundary on either side of RustyAuth.
    // The inbound label sits on the trace's horizontal run; the outbound label sits
    // on the vertical run, where the board is open.
    const annotateFlow = (traceIndex: number, text: string, run: "horizontal" | "vertical") => {
      const [fromX, fromZ] = stationPositions[traceIndex];
      const [toX, toZ] = stationPositions[traceIndex + 1];
      const anchor = new THREE.Group();
      if (run === "horizontal") {
        anchor.position.set((fromX + 1.05 + toX) / 2, 0, fromZ);
      } else {
        const edge = fromZ > toZ ? 1 : -1;
        anchor.position.set(toX, 0, (fromZ + toZ + edge) / 2);
      }
      world.add(anchor);
      addStepLabel(anchor, "", text, 0.18, "flow");
    };
    if (rustyIndex > 0) annotateFlow(rustyIndex - 1, "Passkey proof", "horizontal");
    if (rustyIndex < props.steps.length - 1) {
      // A step named "Private …" is RustyAuth's own store; anything else consumes claims.
      const privateState = /private/i.test(props.steps[rustyIndex + 1][1]);
      annotateFlow(rustyIndex, privateState ? "Private state" : "Narrow claims", "vertical");
    }

    const pulses: Array<{ path: THREE.CurvePath<THREE.Vector3>; dot: THREE.Mesh; offset: number }> = [];
    traces.forEach((path, traceIndex) => {
      const color = traceIndex >= rustyIndex ? palette.copper : palette.ink;
      for (let index = 0; index < 3; index += 1) {
        const dot = new THREE.Mesh(
          trackGeometry(new THREE.SphereGeometry(0.055, 12, 12)),
          fill(color),
        );
        world.add(dot);
        pulses.push({ path, dot, offset: index / 3 + traceIndex * 0.12 });
      }
    });

    const resize = () => {
      const width = host.clientWidth;
      const height = host.clientHeight;
      if (!width || !height) return;
      renderer.setSize(width, height, false);
      labels.setSize(width, height);
      const aspect = width / height;
      const frustum = Math.max(7.8, 11.2 / aspect);
      camera.left = (-frustum * aspect) / 2;
      camera.right = (frustum * aspect) / 2;
      camera.top = frustum / 2;
      camera.bottom = -frustum / 2;
      camera.updateProjectionMatrix();
    };
    const resizeObserver = new ResizeObserver(resize);
    resizeObserver.observe(host);
    resize();

    const pointer = { x: 0, y: 0, targetX: 0, targetY: 0 };
    const onPointerMove = (event: PointerEvent) => {
      const bounds = host.getBoundingClientRect();
      pointer.targetX = ((event.clientX - bounds.left) / bounds.width) * 2 - 1;
      pointer.targetY = ((event.clientY - bounds.top) / bounds.height) * 2 - 1;
    };
    const onPointerLeave = () => {
      pointer.targetX = 0;
      pointer.targetY = 0;
    };
    host.addEventListener("pointermove", onPointerMove);
    host.addEventListener("pointerleave", onPointerLeave);

    const startedAt = performance.now();
    let frame = 0;
    const render = (now: number) => {
      const seconds = now / 1000;
      const intro = reducedMotion ? 1 : 1 - Math.pow(1 - Math.min((now - startedAt) / 1150, 1), 3);
      stations.forEach(({ group }, index) => {
        const delay = Math.min(Math.max(intro * 1.55 - index * 0.16, 0), 1);
        group.position.y = (1 - delay) * 0.7;
        group.scale.setScalar(0.9 + delay * 0.1);
      });
      rustyLayers.forEach((layer) => {
        layer.group.position.y = layer.settled * (0.4 + 0.6 * intro) +
          (reducedMotion ? 0 : Math.sin(seconds * 0.75 + layer.phase) * 0.03 * intro);
      });
      pulses.forEach((pulse) => {
        const position = reducedMotion ? pulse.offset % 1 : (seconds * 0.14 + pulse.offset) % 1;
        pulse.dot.position.copy(pulse.path.getPoint(position));
        pulse.dot.position.y = 0.06;
      });
      if (!reducedMotion) {
        pointer.x += (pointer.targetX - pointer.x) * 0.035;
        pointer.y += (pointer.targetY - pointer.y) * 0.035;
        world.rotation.y = baseYaw + pointer.x * 0.045 + Math.sin(seconds * 0.08) * 0.02;
        world.rotation.x = pointer.y * 0.022;
        if (tokenDisc) tokenDisc.rotation.y = seconds * 0.28;
      }
      renderer.render(scene, camera);
      labels.render(scene, camera);
      frame = requestAnimationFrame(render);
    };
    render(performance.now());

    onCleanup(() => {
      cancelAnimationFrame(frame);
      resizeObserver.disconnect();
      host.removeEventListener("pointermove", onPointerMove);
      host.removeEventListener("pointerleave", onPointerLeave);
      resources.dispose();
      renderer.dispose();
      labels.domElement.remove();
      canvas.remove();
    });
  });

  return (
    <div class="solution-boundary solution-boundary-3d" aria-label={`${props.sector} reference architecture`}>
      <div class="solution-boundary-header">
        <span>4-step authentication path</span>
        <strong>Customer boundary</strong>
      </div>
      <div class="solution-boundary-stage" ref={host} aria-hidden="true" />
      <ol class="solution-boundary-legend">
        <For each={props.steps}>
          {([number, title, detail], index) => (
            <li class={index() === rustyIndex ? "active" : ""}>
              <span>{number}</span>
              <div>
                <strong>{title}</strong>
                <small>{detail}</small>
              </div>
            </li>
          )}
        </For>
      </ol>
    </div>
  );
}
