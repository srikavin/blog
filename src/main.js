import renderMathInElement from 'katex/contrib/auto-render/auto-render'
import 'katex/dist/katex.css'
import 'normalize.css/normalize.css'
import "./main.scss"

renderMathInElement(document.body, {
    delimiters: [
        {left: "$$", right: "$$", display: true},
        {left: "$", right: "$", display: false},
        {left: "\\(", right: "\\)", display: false},
        {left: "\\[", right: "\\]", display: true}
    ]
});

const headings = [];

document.querySelectorAll('.blog-scrollspy a').forEach((val) => {
    const target = document.getElementById(val.dataset.target);
    headings.push({name: val.innerText, scrollSpyEl: val, target: target})
});

headings.sort((a, b) => a.position - b.position);

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

window.addEventListener('scroll', scrollListener, {passive: true})
scrollListener();
