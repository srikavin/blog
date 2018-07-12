import * as React from 'react';
import * as ReactMarkdown from 'react-markdown';
import RemarkMathPlugin from 'remark-math';
import MathJax from 'react-mathjax';
import PropTypes from 'prop-types';
import HighlightedCode from './HighlightedCode/HighlightedCode';

class MarkdownRender extends React.Component {
    constructor(props) {
        super(props);
    }


    render() {
        const newProps = {
            ...this.props.options,
            source: this.props.source,
            plugins: [
                RemarkMathPlugin
            ],
            renderers: {
                ...this.props.renderers,
                paragraph: (props) => <div>{props.children} {console.log(props)}</div>,
                link: (props) => <a target={'blank'} href={props.href}>{props.children}</a>,
                inlineCode: (props) => <HighlightedCode {...props}/>,
                code: (props) => <HighlightedCode {...props}/>,
                math: (props) =>
                    <span className={'math'}><MathJax.Node formula={props.value}/></span>,
                inlineMath: (props) =>
                    <span className={'math'}><MathJax.Node inline formula={props.value}/></span>
            }
        };

        return (
            <div ref={this.props.htmlRef} className={this.props.className}>
                <MathJax.Provider>
                    <ReactMarkdown {...newProps} />
                </MathJax.Provider>
            </div>
        );
    }
}

MarkdownRender.propTypes = {
    source: PropTypes.string.isRequired,
    options: PropTypes.object,
    renderers: PropTypes.object,
    className: PropTypes.string,
    htmlRef: PropTypes.object
};

export default MarkdownRender;