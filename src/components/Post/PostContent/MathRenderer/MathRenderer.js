import * as React from 'react';
import * as ReactMarkdown from 'react-markdown';
import MathJax from 'react-mathjax';
import RemarkMathPlugin from 'remark-math';

class MarkdownRender extends React.Component {
    constructor(props) {
        super(props);
    }


    render() {
        const newProps = {
            ...this.props,
            plugins: [
                RemarkMathPlugin,
            ],
            renderers: {
                ...this.props.renderers,
                math: (props) =>
                    <MathJax.Node>{props.value}</MathJax.Node>,
                inlineMath: (props) =>
                    <MathJax.Node inline>{props.value}</MathJax.Node>,
            }
        };

        return (
            <MathJax.Provider didFinishTypeset={this.props.onRenderFinish} input="tex">
                <ReactMarkdown {...newProps} />
            </MathJax.Provider>
        );
    }
}

export default MarkdownRender;