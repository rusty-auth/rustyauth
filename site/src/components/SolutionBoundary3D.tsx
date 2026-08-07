import { For, onCleanup, onMount } from "solid-js";
import * as THREE from "three";
import { CSS2DObject, CSS2DRenderer } from "three/addons/renderers/CSS2DRenderer.js";
import { createSceneResources, palette } from "./auth-flow/scene-primitives.ts";

type BoundaryStep = readonly [string, string, string];

interface SolutionBoundary3DProps {
  sector: string;
  steps: BoundaryStep[];
}

const stationPositions: ReadonlyArray<readonly [number, number]> = [
  [-2.7, 0.85],
  [-0.9, -0.75],
  [0.9, 0.85],
  [2.7, -0.75],
];

export default function SolutionBoundary3D(props: SolutionBoundary3DProps) {
  let host!: HTMLDivElement;

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
    camera.position.set(0, 8.6, 9.4);
    camera.lookAt(0, 0.18, 0);

    const world = new THREE.Group();
    scene.add(world);

    const resources = createSceneResources();
    const { mesh: draw, plate, trackGeometry, trackMaterial } = resources;

    const board = plate(8.8, 5.25, 0.12, 0x2c2d2f, 0.28);
    board.position.y = -0.18;
    world.add(board);

    const gridPoints: THREE.Vector3[] = [];
    for (let x = -4; x <= 4; x += 0.55) {
      gridPoints.push(new THREE.Vector3(x, -0.04, -2.25), new THREE.Vector3(x, -0.04, 2.25));
    }
    for (let z = -2.25; z <= 2.25; z += 0.55) {
      gridPoints.push(new THREE.Vector3(-4, -0.04, z), new THREE.Vector3(4, -0.04, z));
    }
    const gridGeometry = trackGeometry(new THREE.BufferGeometry().setFromPoints(gridPoints));
    const gridMaterial = trackMaterial(
      new THREE.LineBasicMaterial({ color: 0xfffdfa, transparent: true, opacity: 0.045 }),
    );
    world.add(new THREE.LineSegments(gridGeometry, gridMaterial));

    const pathPoints = stationPositions.map(([x, z]) => new THREE.Vector3(x, 0.12, z));
    const route = new THREE.CatmullRomCurve3(pathPoints, false, "centripetal");
    const routeGeometry = trackGeometry(new THREE.BufferGeometry().setFromPoints(route.getPoints(120)));
    const routeMaterial = trackMaterial(
      new THREE.LineDashedMaterial({
        color: 0xd9824d,
        dashSize: 0.16,
        gapSize: 0.11,
        transparent: true,
        opacity: 0.7,
      }),
    );
    const routeLine = new THREE.Line(routeGeometry, routeMaterial);
    routeLine.computeLineDistances();
    world.add(routeLine);
    const routeTubeGeometry = trackGeometry(new THREE.TubeGeometry(route, 96, 0.022, 8, false));
    const routeTubeMaterial = trackMaterial(
      new THREE.MeshBasicMaterial({ color: 0xe69a6a, transparent: true, opacity: 0.46 }),
    );
    world.add(new THREE.Mesh(routeTubeGeometry, routeTubeMaterial));

    const stations: Array<{ group: THREE.Group; settled: number }> = [];

    props.steps.slice(0, 4).forEach(([number], index) => {
      const [x, z] = stationPositions[index];
      const group = new THREE.Group();
      group.position.set(x, 0, z);
      world.add(group);
      stations.push({ group, settled: index * 0.03 });

      const isRustyAuth = index === 1;
      group.add(plate(1.42, 1.22, isRustyAuth ? 0.2 : 0.12, isRustyAuth ? palette.copper : 0xf7f1e9, 0.16));

      if (index === 0) {
        const screen = draw(new THREE.BoxGeometry(0.78, 0.62, 0.07), palette.white);
        screen.position.set(0, 0.55, 0.04);
        group.add(screen);
        const screenBar = draw(new THREE.BoxGeometry(0.59, 0.07, 0.025), palette.copper);
        screenBar.position.set(0, 0.69, 0.09);
        group.add(screenBar);
        const stand = draw(new THREE.BoxGeometry(0.08, 0.25, 0.08), palette.ink);
        stand.position.set(0, 0.24, 0.04);
        group.add(stand);
      } else if (index === 1) {
        const core = draw(new THREE.CylinderGeometry(0.25, 0.25, 0.27, 32), palette.white);
        core.position.y = 0.35;
        group.add(core);
        const ring = draw(new THREE.TorusGeometry(0.4, 0.07, 12, 36), palette.ink);
        ring.rotation.x = Math.PI / 2;
        ring.position.y = 0.27;
        group.add(ring);
      } else if (index === 2) {
        for (let layer = 0; layer < 3; layer += 1) {
          const disc = draw(
            new THREE.CylinderGeometry(0.37, 0.37, 0.14, 32),
            layer === 2 ? palette.ink : palette.white,
          );
          disc.position.y = 0.2 + layer * 0.15;
          group.add(disc);
        }
      } else {
        const card = plate(0.88, 0.72, 0.07, palette.white, 0.09);
        card.position.y = 0.18;
        group.add(card);
        [0.24, 0.02, -0.2].forEach((row, rowIndex) => {
          const bar = draw(
            new THREE.BoxGeometry(rowIndex === 1 ? 0.52 : 0.65, 0.04, 0.055),
            rowIndex === 0 ? palette.copper : palette.ink,
          );
          bar.position.set(-0.03, 0.28, row);
          group.add(bar);
        });
      }

      const marker = draw(
        new THREE.CylinderGeometry(0.13, 0.13, 0.06, 24),
        isRustyAuth ? palette.white : palette.copper,
      );
      marker.position.set(-0.54, 0.2, -0.42);
      group.add(marker);

      const labelElement = document.createElement("span");
      labelElement.className = isRustyAuth
        ? "boundary-node-number boundary-node-number--active"
        : "boundary-node-number";
      labelElement.textContent = number;
      const label = new CSS2DObject(labelElement);
      label.position.set(-0.54, 0.37, -0.42);
      group.add(label);
    });

    const pulse = draw(new THREE.SphereGeometry(0.1, 18, 18), palette.copper);
    world.add(pulse);
    const pulseHaloMaterial = trackMaterial(
      new THREE.MeshBasicMaterial({ color: 0xf5b181, transparent: true, opacity: 0.28 }),
    );
    const pulseHaloGeometry = trackGeometry(new THREE.SphereGeometry(0.18, 18, 18));
    const pulseHalo = new THREE.Mesh(pulseHaloGeometry, pulseHaloMaterial);
    pulse.add(pulseHalo);

    const resize = () => {
      const width = host.clientWidth;
      const height = host.clientHeight;
      if (!width || !height) return;
      renderer.setSize(width, height, false);
      labels.setSize(width, height);
      const aspect = width / height;
      const frustum = Math.max(6.7, 9.25 / aspect);
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
      const intro = reducedMotion ? 1 : 1 - Math.pow(1 - Math.min((now - startedAt) / 1050, 1), 3);
      stations.forEach(({ group, settled }, index) => {
        const delay = Math.min(Math.max(intro * 1.55 - index * 0.18, 0), 1);
        group.position.y = settled + (1 - delay) * 0.8;
        group.scale.setScalar(0.88 + delay * 0.12);
      });

      const progress = reducedMotion ? 0.34 : (seconds * 0.095) % 1;
      const pulsePosition = route.getPoint(progress);
      const segmentProgress = (progress * (props.steps.length - 1)) % 1;
      pulsePosition.y += 0.2 + Math.sin(segmentProgress * Math.PI) * 0.55;
      pulse.position.copy(pulsePosition);
      pulseHalo.scale.setScalar(1 + Math.sin(seconds * 3.2) * 0.16);

      if (!reducedMotion) {
        pointer.x += (pointer.targetX - pointer.x) * 0.04;
        pointer.y += (pointer.targetY - pointer.y) * 0.04;
        world.rotation.y = pointer.x * 0.025;
        world.rotation.x = pointer.y * 0.012;
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
            <li class={index() === 1 ? "active" : ""}>
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
