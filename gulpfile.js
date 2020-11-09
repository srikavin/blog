import * as rollup from "rollup";
import resolve from "@rollup/plugin-node-resolve";
import commonjs from "@rollup/plugin-commonjs";
import postcss from "rollup-plugin-postcss";
import {terser} from "rollup-plugin-terser";

import gulp from 'gulp';
import imagemin from "gulp-imagemin";
import htmlmin from 'gulp-html-minifier-terser';

import {runZola} from "./bin/zola.js";

const prepackage = () => {
    return rollup.rollup({
        input: ['src/main.js'],
        plugins: [
            resolve(),
            commonjs(),
            postcss({
                use: ['sass'],
                extract: true,
                minimize: true
            }),
            terser()
        ]
    }).then(bundle => {
        return bundle.write({
            file: 'static/bundle.js',
            format: 'iife',
            sourcemap: true,
        });
    });
};

const zolaBuild = async () => {
    runZola(['build']);
};

export const postProcessHtml = () => {
    return gulp.src('public/**/*.html')
        .pipe(htmlmin({
            collapseWhitespace: true,
            collapseBooleanAttributes: true,
            minifyCss: true,
            minifyJs: true,
            removeComments: true,
            sortAttributes: true,
            sortClassName: true

        }))
        .pipe(gulp.dest('public/'))
}

export const postProcessImages = () => {
    return gulp.src(['public/posts/**/*.png', 'public/posts/**/*.jpg', 'public/posts/**/*.gif', /*gu'public/posts/!**!/!*.svg'*/])
        .pipe(imagemin([]))
        .pipe(gulp.dest('public/posts/'))
}

export const watch = async () => {
    gulp.watch(['src/**/*'], gulp.series(prepackage));
}

export default gulp.series(prepackage, zolaBuild, postProcessHtml, postProcessImages);
