import { defineConfig } from 'vite';
import { copyFileSync, mkdirSync } from 'fs';
import { resolve } from 'path';

export default defineConfig({
    build: {
        outDir: 'dist-browser',
        emptyOutDir: true,
        lib: {
            entry: 'src/demo.ts',
            name: 'BlindVaultDemo',
            formats: ['iife'],
            fileName: () => 'demo.js',
        },
        rollupOptions: {
            output: {
                entryFileNames: 'assets/demo.js',
            },
        },
    },
    plugins: [
        {
            name: 'copy-browser-index',
            closeBundle() {
                mkdirSync(resolve('dist-browser/assets'), { recursive: true });
                copyFileSync(resolve('browser-index.html'), resolve('dist-browser/index.html'));
            },
        },
    ],
});
