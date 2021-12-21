import renderMathInElement from 'katex/dist/contrib/auto-render.min.js'
import 'katex/dist/katex.css'
import 'normalize.css/normalize.css'
import "./main.scss"

renderMathInElement(document.body, {
    delimiters: [
        {left: "$$", right: "$$", display: true},
        {left: "$", right: "$", display: false},
        {left: "\\(", right: "\\)", display: false},
        {left: "\\[", right: "\\]", display: true}
    ],
    preProcess: (math) => math.replaceAll('\\\n', '\\\\')
});

const headings = [];

document.querySelectorAll('.blog-scrollspy a').forEach((val) => {
    const target = document.getElementById(val.dataset.target);
    headings.push({name: val.innerText, scrollSpyEl: val, target: target})
});

headings.sort((a, b) => a.position - b.position);

function throttle(func, wait = 100) {
    let timer = null;
    return function (...args) {
        if (timer === null) {
            timer = setTimeout(() => {
                func.apply(this, args);
                timer = null;
            }, wait);
        }
    };
}

const scrollListener = () => {
    const scroll = window.scrollY;
    let curObj = undefined;

    headings.forEach((val) => {
        if (val.target.offsetTop - 20 < scroll) {
            curObj = val;
        }
        if (val) {
            val.scrollSpyEl.classList.remove('active');
        }
    });

    if (curObj) {
        curObj.scrollSpyEl.classList.add('active')
    }
};

window.addEventListener('scroll', throttle(scrollListener, 100))
scrollListener();
