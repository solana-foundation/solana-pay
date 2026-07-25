#!/usr/bin/env node

import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const packageManifestPath = resolve(
  repositoryRoot,
  "typescript/packages/solana-pay/core/package.json",
);
const releaseWorkflowPath = resolve(
  repositoryRoot,
  ".github/workflows/release-cli.yml",
);
const ciWorkflowPath = resolve(repositoryRoot, ".github/workflows/ci.yml");
const binaryName = "pay";

function artifactName(target) {
  const extension = target.endsWith("-pc-windows-msvc") ? "zip" : "tar.gz";
  return `${binaryName}-${target}.${extension}`;
}

function uniqueSorted(values) {
  return [...new Set(values)].sort();
}

function setDifference(left, right) {
  return left.filter((value) => !right.includes(value));
}

function workflowTargets(workflow, workflowPath) {
  const targets = [...workflow.matchAll(/^\s*- target:\s*([^\s#]+)\s*$/gm)].map(
    ([, target]) => target,
  );

  if (targets.length === 0) {
    throw new Error(
      `No targets found in ${workflowPath}. Keep the build matrix target entries on their own lines.`,
    );
  }

  if (new Set(targets).size !== targets.length) {
    throw new Error(`Duplicate targets found in ${workflowPath}.`);
  }

  return uniqueSorted(targets);
}

function manifestTargets(manifest) {
  if (
    !manifest.supportedPlatforms ||
    typeof manifest.supportedPlatforms !== "object"
  ) {
    throw new Error(`${packageManifestPath} must define supportedPlatforms.`);
  }

  return uniqueSorted(
    Object.entries(manifest.supportedPlatforms).map(([target, metadata]) => {
      if (!metadata || typeof metadata.artifact !== "string") {
        throw new Error(
          `supportedPlatforms.${target} must define an artifact.`,
        );
      }

      const expected = artifactName(target);
      if (metadata.artifact !== expected) {
        throw new Error(
          `supportedPlatforms.${target}.artifact is ${metadata.artifact}; expected ${expected}.`,
        );
      }

      const expectedBinary = target.endsWith("-pc-windows-msvc")
        ? `${binaryName}.exe`
        : binaryName;
      if (metadata.binary !== expectedBinary) {
        throw new Error(
          `supportedPlatforms.${target}.binary is ${metadata.binary}; expected ${expectedBinary}.`,
        );
      }

      return target;
    }),
  );
}

function printDifference(label, values) {
  if (values.length === 0) {
    return;
  }

  console.error(`${label}:`);
  for (const value of values) {
    console.error(`  - ${value}`);
  }
}

function main() {
  const packageManifest = JSON.parse(readFileSync(packageManifestPath, "utf8"));
  const npmTargets = manifestTargets(packageManifest);
  const releaseTargets = workflowTargets(
    readFileSync(releaseWorkflowPath, "utf8"),
    releaseWorkflowPath,
  );
  const ciTargets = workflowTargets(
    readFileSync(ciWorkflowPath, "utf8"),
    ciWorkflowPath,
  );
  const onlyDeclared = setDifference(npmTargets, releaseTargets);
  const onlyReleased = setDifference(releaseTargets, npmTargets);
  const onlyReleasedNotCi = setDifference(releaseTargets, ciTargets);
  const onlyCiNotReleased = setDifference(ciTargets, releaseTargets);

  if (
    onlyDeclared.length > 0 ||
    onlyReleased.length > 0 ||
    onlyReleasedNotCi.length > 0 ||
    onlyCiNotReleased.length > 0
  ) {
    console.error("Native release artifact contract failed.");
    console.error(`npm manifest: ${packageManifestPath}`);
    console.error(`release matrix: ${releaseWorkflowPath}`);
    console.error(`PR build matrix: ${ciWorkflowPath}`);
    printDifference(
      "Declared by npm but not produced by release",
      onlyDeclared,
    );
    printDifference(
      "Produced by release but not declared by npm",
      onlyReleased,
    );
    printDifference(
      "Produced by release but not built in PR CI",
      onlyReleasedNotCi,
    );
    printDifference(
      "Built in PR CI but not produced by release",
      onlyCiNotReleased,
    );
    process.exitCode = 1;
    return;
  }

  console.log(
    `Native release artifact contract passed for ${npmTargets.length} targets across npm, release, and PR CI.`,
  );
}

main();
