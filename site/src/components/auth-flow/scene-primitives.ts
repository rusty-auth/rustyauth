import * as THREE from "three";
import { CSS2DObject } from "three/addons/renderers/CSS2DRenderer.js";

export const palette = {
  ink: 0x252321,
  inkSoft: 0x625c56,
  white: 0xfffdfa,
  paperDeep: 0xe8dfd4,
  copper: 0xcc5a19,
} as const;

export type SceneResources = ReturnType<typeof createSceneResources>;

/** Owns every GPU resource created by the hero so teardown remains complete. */
export function createSceneResources() {
  const geometries: THREE.BufferGeometry[] = [];
  const materials: THREE.Material[] = [];

  const material = (color: number) => {
    const value = new THREE.MeshBasicMaterial({ color });
    materials.push(value);
    return value;
  };

  const inkEdge = new THREE.LineBasicMaterial({ color: palette.ink });
  const softEdge = new THREE.LineBasicMaterial({ color: palette.inkSoft });
  materials.push(inkEdge, softEdge);

  const mesh = (geometry: THREE.BufferGeometry, color: number) => {
    geometries.push(geometry);
    const object = new THREE.Mesh(geometry, material(color));
    const edgeGeometry = new THREE.EdgesGeometry(geometry, 18);
    geometries.push(edgeGeometry);
    object.add(new THREE.LineSegments(edgeGeometry, color === palette.ink ? softEdge : inkEdge));
    return object;
  };

  const plate = (width: number, depth: number, height: number, color: number, radius = 0.16) => {
    const shape = roundedRectangle(width, depth, radius);
    const geometry = new THREE.ExtrudeGeometry(shape, { depth: height, bevelEnabled: false });
    geometry.rotateX(-Math.PI / 2);
    return mesh(geometry, color);
  };

  const trackGeometry = <T extends THREE.BufferGeometry>(geometry: T): T => {
    geometries.push(geometry);
    return geometry;
  };

  const trackMaterial = <T extends THREE.Material>(value: T): T => {
    materials.push(value);
    return value;
  };

  const dispose = () => {
    geometries.forEach((geometry) => geometry.dispose());
    materials.forEach((value) => value.dispose());
  };

  return { dispose, material, mesh, plate, trackGeometry, trackMaterial };
}

export function addLabel(
  parent: THREE.Object3D,
  title: string,
  position: readonly [number, number, number],
  variant: "" | "accent" | "layer" = "",
) {
  const element = document.createElement("span");
  element.className = variant ? `auth-scene-label auth-scene-label--${variant}` : "auth-scene-label";
  element.textContent = title;
  const object = new CSS2DObject(element);
  object.position.set(...position);
  parent.add(object);
  return object;
}

export function createTrace(points: ReadonlyArray<readonly [number, number]>) {
  const path = new THREE.CurvePath<THREE.Vector3>();
  const vectors = points.map(([x, z]) => new THREE.Vector3(x, 0.035, z));
  for (let index = 0; index < vectors.length - 1; index += 1) {
    path.add(new THREE.LineCurve3(vectors[index], vectors[index + 1]));
  }
  return path;
}

function roundedRectangle(width: number, depth: number, radius: number) {
  const shape = new THREE.Shape();
  const x = -width / 2;
  const y = -depth / 2;
  shape.moveTo(x + radius, y);
  shape.lineTo(x + width - radius, y);
  shape.absarc(x + width - radius, y + radius, radius, -Math.PI / 2, 0, false);
  shape.lineTo(x + width, y + depth - radius);
  shape.absarc(x + width - radius, y + depth - radius, radius, 0, Math.PI / 2, false);
  shape.lineTo(x + radius, y + depth);
  shape.absarc(x + radius, y + depth - radius, radius, Math.PI / 2, Math.PI, false);
  shape.lineTo(x, y + radius);
  shape.absarc(x + radius, y + radius, radius, Math.PI, Math.PI * 1.5, false);
  return shape;
}
