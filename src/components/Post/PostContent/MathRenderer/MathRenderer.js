import * as React from 'react';
import * as ReactMarkdown from 'react-markdown';
import RemarkMathPlugin from '@ibrahima/remark-math';
import MathJax from 'react-mathjax';
import PropTypes from 'prop-types';
import HighlightedCode from './HighlightedCode/HighlightedCode';
import ImageRenderer from './ImageRenderer/ImageRenderer';
import styles from './MathRenderer.module.css'


class MarkdownRender extends React.Component {
    render() {
        const newProps = {
            ...this.props.options,
            source: this.props.source,
            plugins: [
                RemarkMathPlugin
            ],
            renderers: {
                ...this.props.renderers,
                paragraph: (props) => <div>{props.children}</div>,
                link: (props) => <a target={'_blank'} href={props.href}>{props.children}</a>,
                inlineCode: (props) => <HighlightedCode inline={true} {...props}/>,
                code: (props) => <HighlightedCode {...props}/>,
                math: (props) =>
                    <span className={styles.mathContainer}><MathJax.Node formula={props.value}/></span>,
                inlineMath: (props) =>
                    <span className={`${styles.mathContainer} ${styles.inline}`}><MathJax.Node inline
                                                                                               formula={props.value}/></span>,
                image: ImageRenderer
            }
        };

        return (
            <div ref={this.props.htmlRef} className={this.props.className}>
                <MathJax.Provider>
                    <ReactMarkdown className={this.props.markdownClassName} {...newProps} />
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
    markdownClassName: PropTypes.string,
    htmlRef: PropTypes.object
};

export default MarkdownRender;