/**
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

export interface EstimatedValue {
  mean: number;
  uncertainty: number;
}

function sum(values: number[]): number {
  return values.reduce((r, x) => r + x, 0);
}

// Given a set of repeated measurements, calculates mean value and error bar.
export function estimateMeasurements(values: number[]): EstimatedValue {
  const mean = sum(values) / values.length;
  const stddev = Math.sqrt(
    sum(values.map(x => (x - mean) ** 2)) / values.length
  );
  return {
    mean,
    uncertainty: stddev / Math.sqrt(values.length - 1),
  };
}

export function formatEstimatedValue(x: EstimatedValue): string {
  return `${x.mean.toFixed(0)} ± ${x.uncertainty.toFixed(0)}`;
}
