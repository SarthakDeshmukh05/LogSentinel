// ML Detector — Lightweight Isolation Forest anomaly detection (iterative, WASM-safe)

import { getFeatureVector, FEATURE_NAMES } from './featureEngineer';

function averagePathLength(n) {
  if (n <= 1) return 0;
  if (n === 2) return 1;
  const H = Math.log(n - 1) + 0.5772156649;
  return 2 * H - (2 * (n - 1)) / n;
}

// Seeded pseudo-random number generator (deterministic)
function createRNG(seed) {
  let s = seed;
  return function () {
    s = (s * 16807 + 0) % 2147483647;
    return s / 2147483647;
  };
}

// Build a single isolation tree iteratively using a stack
function buildTree(data, maxDepth, rng) {
  const nodes = [];
  const stack = [{ data, depth: 0, nodeIndex: 0 }];
  nodes.push(null); // reserve node 0

  while (stack.length > 0) {
    const { data: subset, depth, nodeIndex } = stack.pop();

    if (subset.length <= 1 || depth >= maxDepth) {
      nodes[nodeIndex] = { type: 'leaf', size: subset.length, depth };
      continue;
    }

    const numFeatures = subset[0].length;
    const featureIdx = Math.floor(rng() * numFeatures);
    let min = Infinity, max = -Infinity;

    for (let i = 0; i < subset.length; i++) {
      const v = subset[i][featureIdx];
      if (!isNaN(v)) {
        if (v < min) min = v;
        if (v > max) max = v;
      }
    }

    if (min === max || !isFinite(min)) {
      nodes[nodeIndex] = { type: 'leaf', size: subset.length, depth };
      continue;
    }

    const splitValue = min + rng() * (max - min);
    const left = [];
    const right = [];

    for (let i = 0; i < subset.length; i++) {
      if (subset[i][featureIdx] < splitValue) {
        left.push(subset[i]);
      } else {
        right.push(subset[i]);
      }
    }

    if (left.length === 0 || right.length === 0) {
      nodes[nodeIndex] = { type: 'leaf', size: subset.length, depth };
      continue;
    }

    const leftIdx = nodes.length;
    nodes.push(null);
    const rightIdx = nodes.length;
    nodes.push(null);

    nodes[nodeIndex] = {
      type: 'internal',
      featureIdx,
      splitValue,
      leftIdx,
      rightIdx,
      depth,
    };

    stack.push({ data: left, depth: depth + 1, nodeIndex: leftIdx });
    stack.push({ data: right, depth: depth + 1, nodeIndex: rightIdx });
  }

  return nodes;
}

// Compute path length for a point through a tree (iterative)
function pathLength(point, nodes) {
  let idx = 0;
  let currentDepth = 0;

  while (idx < nodes.length && nodes[idx]) {
    const node = nodes[idx];
    if (node.type === 'leaf') {
      return currentDepth + averagePathLength(node.size);
    }

    const value = point[node.featureIdx];
    if (isNaN(value)) {
      return currentDepth + averagePathLength(2);
    }

    currentDepth++;
    if (value < node.splitValue) {
      idx = node.leftIdx;
    } else {
      idx = node.rightIdx;
    }
  }

  return currentDepth;
}

function isolationForestTrain(data, nEstimators, maxSamples, seed) {
  const trees = [];
  const rng = createRNG(seed);
  const maxDepth = Math.ceil(Math.log2(Math.min(maxSamples, data.length)));
  const sampleSize = Math.min(maxSamples, data.length);

  for (let t = 0; t < nEstimators; t++) {
    // Sample without replacement
    const indices = [];
    const used = new Set();
    while (indices.length < sampleSize) {
      const i = Math.floor(rng() * data.length);
      if (!used.has(i)) {
        used.add(i);
        indices.push(i);
      }
    }
    const sample = indices.map(i => data[i]);
    trees.push(buildTree(sample, maxDepth, rng));
  }

  return { trees, maxSamples: sampleSize };
}

function isolationForestScore(point, model) {
  const { trees, maxSamples } = model;
  if (trees.length === 0) return 0;

  let totalPath = 0;
  for (const tree of trees) {
    totalPath += pathLength(point, tree);
  }
  const avgPath = totalPath / trees.length;
  const c = averagePathLength(maxSamples);
  return -(Math.pow(2, -(avgPath / c)));
}

// Simplified feature importance via perturbation
function computeImportance(model, point) {
  const baseScore = isolationForestScore(point, model);
  const importances = [];

  for (let i = 0; i < point.length; i++) {
    const perturbed = [...point];
    perturbed[i] = 0; // perturb to zero (mean of normalized)
    const newScore = isolationForestScore(perturbed, model);
    importances.push({
      feature: FEATURE_NAMES[i] || `feature_${i}`,
      importance: Math.round(Math.abs(baseScore - newScore) * 10000) / 10000,
      direction: newScore > baseScore ? 'increases_anomaly' : 'decreases_anomaly',
    });
  }

  return importances.sort((a, b) => b.importance - a.importance);
}

export function runMLDetection(events, options = {}) {
  try {
    const vectors = events.map(e => getFeatureVector(e));
    const validIndices = [];
    const validVectors = [];

    for (let i = 0; i < vectors.length; i++) {
      if (vectors[i].length > 0 && vectors[i].every(x => isFinite(x) && !isNaN(x))) {
        validIndices.push(i);
        validVectors.push(vectors[i]);
      }
    }

    if (validVectors.length < 30) {
      return events.map(evt => ({
        ...evt,
        ml_detection: {
          anomaly_score: 0,
          anomaly_score_normalized: 0,
          is_anomaly: false,
          feature_importances: [],
          model_status: 'insufficient_data',
        },
      }));
    }

    // Normalize features
    const numFeatures = validVectors[0].length;
    const means = new Array(numFeatures).fill(0);
    const stds = new Array(numFeatures).fill(0);

    for (const vec of validVectors) {
      for (let i = 0; i < numFeatures; i++) {
        means[i] += vec[i];
      }
    }
    for (let i = 0; i < numFeatures; i++) means[i] /= validVectors.length;

    for (const vec of validVectors) {
      for (let i = 0; i < numFeatures; i++) {
        stds[i] += (vec[i] - means[i]) ** 2;
      }
    }
    for (let i = 0; i < numFeatures; i++) stds[i] = Math.sqrt(stds[i] / validVectors.length) || 1;

    const normalized = validVectors.map(vec =>
      vec.map((v, i) => (v - means[i]) / stds[i])
    );

    // Train
    const model = isolationForestTrain(
      normalized,
      50,  // nEstimators (reduced to 50 for extreme speed on 10k logs)
      Math.min(128, Math.floor(normalized.length * 0.8)),
      42
    );

    // Score all valid vectors and apply threshold
    const scores = normalized.map(p => isolationForestScore(p, model));
    const sortedScores = [...scores].sort((a, b) => a - b);
    
    // Convert 0-1 scale to percentile (default 8% if unspecified)
    const sensitivity = options.anomalyThreshold !== undefined ? parseFloat(options.anomalyThreshold) : 0.08;
    const threshold = sortedScores[Math.floor(sortedScores.length * sensitivity)] || -0.55;

    // Map back to events
    const validSet = new Set(validIndices);
    let validIdx = 0;

    return events.map((evt, idx) => {
      if (!validSet.has(idx)) {
        return {
          ...evt,
          ml_detection: {
            anomaly_score: 0,
            anomaly_score_normalized: 0,
            is_anomaly: false,
            feature_importances: [],
            model_status: 'skipped',
          },
        };
      }

      const score = scores[validIdx];
      const normalizedScore = Math.min(1, Math.max(0, ((-score - 0.4) / 0.3)));
      const isAnomaly = score < threshold;

      let feature_importances = [];
      if (isAnomaly) {
        feature_importances = computeImportance(model, normalized[validIdx]).slice(0, 5);
      }

      validIdx++;

      return {
        ...evt,
        ml_detection: {
          anomaly_score: Math.round(score * 10000) / 10000,
          anomaly_score_normalized: Math.round(normalizedScore * 1000) / 1000,
          is_anomaly: isAnomaly,
          feature_importances,
          model_status: 'active',
        },
      };
    });
  } catch (err) {
    console.error('ML Detection error:', err);
    return events.map(evt => ({
      ...evt,
      ml_detection: {
        anomaly_score: 0,
        anomaly_score_normalized: 0,
        is_anomaly: false,
        feature_importances: [],
        model_status: 'error: ' + err.message,
      },
    }));
  }
}

export default { runMLDetection };
