import { onCleanup, onMount } from "solid-js";
import * as THREE from "three";
import { CSS2DRenderer } from "three/addons/renderers/CSS2DRenderer.js";
import { addLabel, createSceneResources, createTrace, palette } from "./auth-flow/scene-primitives.ts";

export default function AuthFlow3D() {
  let host!: HTMLDivElement;

  onMount(() => {
    const reducedMotion = globalThis.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const canvas = document.createElement("canvas");
    host.append(canvas);
    const renderer = new THREE.WebGLRenderer({ canvas, alpha: true, antialias: true });
    renderer.setPixelRatio(Math.min(globalThis.devicePixelRatio, 2));
    renderer.outputColorSpace = THREE.SRGBColorSpace;

    const labels = new CSS2DRenderer();
    labels.domElement.className = "auth-scene-labels";
    host.append(labels.domElement);

    const scene = new THREE.Scene();
    const camera = new THREE.OrthographicCamera(-1, 1, 1, -1, 0.1, 100);
    camera.position.set(7.2, 7.5, 7.2);
    camera.lookAt(0.05, 0.25, 0);

    const world = new THREE.Group();
    const baseYaw = -0.14;
    world.rotation.y = baseYaw;
    scene.add(world);

    const resources = createSceneResources();
    const { material: fill, mesh: draw, plate, trackGeometry, trackMaterial } = resources;

    const board = plate(9.2, 6.15, 0.14, palette.white, 0.42);
    board.position.y = -0.16;
    world.add(board);

    const gridPoints: THREE.Vector3[] = [];
    for (let x = -4.15; x <= 4.15; x += 0.7) {
      gridPoints.push(new THREE.Vector3(x, 0.005, -2.7), new THREE.Vector3(x, 0.005, 2.7));
    }
    for (let z = -2.7; z <= 2.7; z += 0.7) {
      gridPoints.push(new THREE.Vector3(-4.15, 0.005, z), new THREE.Vector3(4.15, 0.005, z));
    }
    const gridGeometry = trackGeometry(new THREE.BufferGeometry().setFromPoints(gridPoints));
    const gridMaterial = trackMaterial(
      new THREE.LineBasicMaterial({ color: palette.ink, transparent: true, opacity: 0.065 }),
    );
    world.add(new THREE.LineSegments(gridGeometry, gridMaterial));

    const application = new THREE.Group();
    application.position.set(-3.25, 0, -0.7);
    world.add(application);
    application.add(plate(2.05, 2.1, 0.07, palette.white, 0.18));
    const screenStand = draw(new THREE.BoxGeometry(0.14, 0.48, 0.12), palette.ink);
    screenStand.position.set(0, 0.24, 0.05);
    application.add(screenStand);
    const screen = draw(new THREE.BoxGeometry(1.55, 1.02, 0.09), palette.white);
    screen.position.set(0, 1.05, 0.06);
    application.add(screen);
    const screenBar = draw(new THREE.BoxGeometry(1.25, 0.12, 0.04), palette.copper);
    screenBar.position.set(0, 1.29, 0.12);
    application.add(screenBar);
    const credential = draw(new THREE.TorusGeometry(0.23, 0.055, 12, 36), palette.ink);
    credential.position.set(-0.28, 1.02, 0.13);
    application.add(credential);
    const keyStem = draw(new THREE.BoxGeometry(0.44, 0.08, 0.06), palette.ink);
    keyStem.position.set(0.02, 0.86, 0.13);
    keyStem.rotation.z = -0.5;
    application.add(keyStem);
    addLabel(application, "Your application", [0, 1.85, 0]);

    const stack = new THREE.Group();
    stack.position.set(0.15, 0, -0.05);
    stack.scale.setScalar(0.92);
    world.add(stack);
    const layerData: Array<{ group: THREE.Group; settled: number; phase: number }> = [];
    const addLayer = (settled: number, phase: number) => {
      const group = new THREE.Group();
      group.position.y = settled;
      stack.add(group);
      layerData.push({ group, settled, phase });
      return group;
    };
    const storeLayer = addLayer(0, 0);
    storeLayer.add(plate(2.75, 2.75, 0.22, palette.ink, 0.24));
    addLabel(storeLayer, "Session ledger", [-1.48, 0.24, 1.25], "layer");
    const ceremonyLayer = addLayer(0.93, 1.4);
    ceremonyLayer.add(plate(2.35, 2.35, 0.13, palette.white, 0.2));
    const chips: Array<[number, number, number, number]> = [
      [-0.62, -0.55, 0.48, 0.42],
      [0.35, -0.52, 0.38, 0.38],
      [-0.48, 0.43, 0.38, 0.38],
      [0.5, 0.44, 0.62, 0.34],
    ];
    chips.forEach(([x, z, width, depth], index) => {
      const chip = draw(
        new THREE.BoxGeometry(width, 0.1, depth),
        index === 0 ? palette.copper : palette.paperDeep,
      );
      chip.position.set(x, 0.17, z);
      ceremonyLayer.add(chip);
    });
    addLabel(ceremonyLayer, "WebAuthn ceremony", [-1.3, 0.2, 1.02], "layer");
    const verifyLayer = addLayer(1.86, 2.8);
    verifyLayer.add(plate(1.9, 1.9, 0.13, palette.white, 0.19));
    const verifyRing = draw(new THREE.TorusGeometry(0.52, 0.12, 16, 50), palette.ink);
    verifyRing.rotation.x = Math.PI / 2;
    verifyRing.position.y = 0.17;
    verifyLayer.add(verifyRing);
    const verifyCore = draw(new THREE.CylinderGeometry(0.14, 0.14, 0.34, 24), palette.copper);
    verifyCore.position.y = 0.26;
    verifyLayer.add(verifyCore);
    addLabel(verifyLayer, "Verify identity", [-1.05, 0.2, 0.82], "layer");
    const tokenLayer = addLayer(2.79, 4.2);
    tokenLayer.add(plate(1.35, 1.35, 0.15, palette.copper, 0.18));
    const tokenDisc = draw(new THREE.CylinderGeometry(0.25, 0.25, 0.12, 36), palette.white);
    tokenDisc.position.y = 0.34;
    tokenLayer.add(tokenDisc);
    addLabel(tokenLayer, "RustyAuth", [0, 0.92, 0], "accent");

    const sable = new THREE.Group();
    sable.position.set(3.15, 0, 1.25);
    world.add(sable);
    sable.add(plate(2.0, 1.7, 0.07, palette.white, 0.18));
    for (let index = 0; index < 3; index += 1) {
      const cylinder = draw(
        new THREE.CylinderGeometry(0.48, 0.48, 0.2, 36),
        index === 1 ? palette.paperDeep : palette.white,
      );
      cylinder.position.set(0, 0.18 + index * 0.24, 0);
      sable.add(cylinder);
    }
    const sableTop = draw(new THREE.CylinderGeometry(0.48, 0.48, 0.08, 36), palette.ink);
    sableTop.position.y = 0.79;
    sable.add(sableTop);
    addLabel(sable, "SableDB · private state", [0, 1.25, 0]);

    const claims = new THREE.Group();
    claims.position.set(3.05, 0, -1.65);
    world.add(claims);
    claims.add(plate(1.85, 1.45, 0.06, palette.white, 0.12));
    [[-0.35, -0.32, 0.8], [-0.35, -0.08, 0.58], [-0.35, 0.16, 0.92]].forEach(([x, z, width], index) => {
      const bar = draw(
        new THREE.BoxGeometry(width, 0.04, 0.07),
        index === 0 ? palette.ink : palette.paperDeep,
      );
      bar.position.set(x + width / 2, 0.09, z);
      claims.add(bar);
    });
    const seal = draw(new THREE.CylinderGeometry(0.22, 0.22, 0.08, 32), palette.copper);
    seal.position.set(0.5, 0.1, 0.38);
    claims.add(seal);
    addLabel(claims, "Signed access token", [0, 0.84, 0], "accent");

    const flows = [
      createTrace([[-2.2, -0.7], [-1.55, -0.7], [-1.55, -0.15], [-1.1, -0.15]]),
      createTrace([[1.35, 0.35], [2.05, 0.35], [2.05, 1.25], [2.35, 1.25]]),
      createTrace([[1.25, -0.45], [2.0, -0.45], [2.0, -1.65], [2.12, -1.65]]),
    ];
    const traceMaterial = trackMaterial(
      new THREE.LineBasicMaterial({ color: palette.ink, transparent: true, opacity: 0.48 }),
    );
    flows.forEach((path) => {
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
    addLabel(world, "Passkey proof", [-1.7, 0.52, -0.3], "layer");
    addLabel(world, "Private Valkey protocol", [2.05, 0.54, 0.92], "layer");

    const pulses: Array<{ path: THREE.CurvePath<THREE.Vector3>; dot: THREE.Mesh; offset: number }> = [];
    flows.forEach((path, flowIndex) => {
      for (let index = 0; index < 3; index += 1) {
        const dot = new THREE.Mesh(
          new THREE.SphereGeometry(0.055, 12, 12),
          fill(flowIndex === 1 ? palette.copper : palette.ink),
        );
        world.add(dot);
        pulses.push({ path, dot, offset: index / 3 + flowIndex * 0.12 });
      }
    });

    const resize = () => {
      const width = host.clientWidth;
      const height = host.clientHeight;
      if (!width || !height) return;
      renderer.setSize(width, height, false);
      labels.setSize(width, height);
      const aspect = width / height;
      // Frame against the model's projected width, including when the scene is
      // used as a tall, quiet background behind the mobile hero copy.
      const frustum = Math.max(9.2, 10.6 / aspect);
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
    host.addEventListener("pointermove", onPointerMove);

    const startedAt = performance.now();
    let frame = 0;
    const render = (now: number) => {
      const seconds = now / 1000;
      const intro = reducedMotion ? 1 : 1 - Math.pow(1 - Math.min((now - startedAt) / 1300, 1), 3);
      layerData.forEach((layer) => {
        layer.group.position.y = layer.settled * (0.35 + 0.65 * intro) +
          Math.sin(seconds * 0.75 + layer.phase) * 0.035 * intro;
      });
      pulses.forEach((pulse) => {
        const position = (seconds * 0.14 + pulse.offset) % 1;
        pulse.dot.position.copy(pulse.path.getPoint(position));
        pulse.dot.position.y = 0.06;
      });
      if (!reducedMotion) {
        pointer.x += (pointer.targetX - pointer.x) * 0.035;
        pointer.y += (pointer.targetY - pointer.y) * 0.035;
        world.rotation.y = baseYaw + pointer.x * 0.045 + Math.sin(seconds * 0.08) * 0.02;
        world.rotation.x = pointer.y * 0.022;
        tokenDisc.rotation.y = seconds * 0.28;
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
      resources.dispose();
      renderer.dispose();
      labels.domElement.remove();
      canvas.remove();
    });
  });

  return (
    <div
      class="flow-stage"
      ref={host}
      role="img"
      aria-label="Animated isometric architecture showing a passkey proof moving from an application through RustyAuth, into private SableDB state, and returning as a signed access token."
    />
  );
}
