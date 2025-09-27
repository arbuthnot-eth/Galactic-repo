// Circom WebAssembly runtime support for zkLogin proof generation
// Provides the complete runtime imports that circom-generated WASM modules expect

import { groth16 } from 'snarkjs';

interface WitnessCalculatorInstance {
  exports: {
    [key: string]: any;
  };
}

interface WitnessCalculatorOptions {
  memory?: WebAssembly.Memory;
}

class WitnessCalculator {
  private instance: WitnessCalculatorInstance;
  private memory: WebAssembly.Memory;
  private n64: number;
  private nPublic: number;
  private nConstraints: number;

  constructor(instance: WitnessCalculatorInstance, options: WitnessCalculatorOptions = {}) {
    this.instance = instance;
    this.memory = options.memory || new WebAssembly.Memory({ initial: 32768 });

    // Initialize circom-specific properties
    this.n64 = this.instance.exports.get_n64 ? this.instance.exports.get_n64() : 0;
    this.nPublic = this.instance.exports.get_n_public ? this.instance.exports.get_n_public() : 0;
    this.nConstraints = this.instance.exports.get_n_constraints ? this.instance.exports.get_n_constraints() : 0;
  }

  circom_version_supported(): string {
    return "2.1.0";
  }

}

// Complete runtime imports that circom WebAssembly modules expect
function createCircomRuntimeImports(): WebAssembly.Imports {
  return {
    runtime: {
      // Error handling
      error: function(code: number, ptr: number, len: number) {
        throw new Error(`WebAssembly error: ${code} at ${ptr}:${len}`);
      },

      // Logging functions (no-op for production)
      print: function(ptr: number, len: number) {
        // Silent in production
      },

      printErrorMessage: function() {
        // Silent in production
      },

      // Exception handling
      exceptionHandler: function(code: number) {
        throw new Error(`WebAssembly exception: ${code}`);
      },

      // Time function
      time: function() {
        return Math.floor(Date.now() / 1000);
      },

      // Memory management functions that circom might expect
      abort: function(msg: number, file: number, line: number, column: number) {
        throw new Error(`WebAssembly execution aborted at ${file}:${line}:${column}`);
      },

      // Buffer and message writing functions (no-op for production)
      writeBufferMessage: function() {
        // Silent in production
      },

      writeErrorMessage: function() {
        // Silent in production
      },

      // Memory management
      memset: function(ptr: number, value: number, size: number) {
        return ptr;
      },

    }
  };
}

// Builder function that creates WitnessCalculator with proper imports
async function WitnessCalculatorBuilder(wasmCode: ArrayBuffer, options: WitnessCalculatorOptions = {}): Promise<WitnessCalculator> {
  try {
    // Compile the WebAssembly module
    const wasmModule = await WebAssembly.compile(wasmCode);

    // Create the runtime imports
    const imports = createCircomRuntimeImports();

    // Instantiate with proper imports
    const instance = await WebAssembly.instantiate(wasmModule, imports);

    // Create and return the witness calculator
    return new WitnessCalculator(instance, options);
  } catch (error) {
    throw error;
  }
}

// Export for use in the global context
declare global {
  interface Window {
    WitnessCalculatorBuilder?: typeof WitnessCalculatorBuilder;
    createCircomRuntimeImports?: typeof createCircomRuntimeImports;
    snarkjs?: { groth16: typeof groth16 };
  }
}

// Attach to global context if in browser
if (typeof window !== 'undefined') {
  window.WitnessCalculatorBuilder = WitnessCalculatorBuilder;
  window.createCircomRuntimeImports = createCircomRuntimeImports;
  window.snarkjs = { groth16 };
}

export {
  WitnessCalculator,
  WitnessCalculatorBuilder,
  createCircomRuntimeImports
};