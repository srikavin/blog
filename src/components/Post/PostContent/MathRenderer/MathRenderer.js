import * as React from 'react';
import * as ReactMarkdown from 'react-markdown';
import RemarkMathPlugin from '@ibrahima/remark-math';
import MathJax from 'react-mathjax';
import PropTypes from 'prop-types';
import HighlightedCode from './HighlightedCode/HighlightedCode';
import ImageRenderer from './ImageRenderer/ImageRenderer';
import styles from './MathRenderer.module.css'
import ParagraphRenderer from "./ParagraphRenderer/ParagraphRenderer";
import LinkRenderer from "./LinkRenderer/LinkRenderer";
import {ThemeContext} from "../../../Theme";
import classNames from 'classnames/bind';

let cx = classNames.bind(styles);

class MarkdownRender extends React.Component {
    static contextType = ThemeContext

    render() {
        let map = {};
        const newProps = {
            ...this.props.options,
            source: this.props.source,
            plugins: [
                RemarkMathPlugin
            ],
            escapeHtml: this.props.trusted !== true,
            renderers: {
                ...this.props.renderers,
                heading: (props) => {
                    let p = {};
                    if (props.children && props.children[0]) {
                        p['id'] = `${props.children[0].props.value}-${props.level}`.replace(/[^a-zA-Z0-9-_]/g, '-');
                    }

                    return React.createElement(`h${props.level}`, p, props.children);
                },
                paragraph: (props) => <ParagraphRenderer settings={map} {...props}/>,
                link: (props) => <LinkRenderer settings={map} {...props}/>,
                inlineCode: (props) => <HighlightedCode inline={true} {...props}/>,
                code: (props) => <HighlightedCode settings={map} {...props}/>,
                math: (props) =>
                    <span className={styles.mathContainer}><MathJax.Node formula={props.value}/></span>,
                inlineMath: (props) =>
                    <span className={`${styles.mathContainer} ${styles.inline}`}><MathJax.Node inline
                                                                                               formula={props.value}/></span>,
                image: (props) => <ImageRenderer settings={map} {...props}/>,
                definition: (p) => {
                    let tmp = {};
                    try {
                        tmp[p.identifier] = JSON.parse(p.url);
                        map = Object.assign({}, map, tmp);
                    } catch (e) {
                        tmp[p.identifier] = p.url;
                        map = Object.assign({}, map, tmp);
                    }
                    return null;
                },
                blockquote: (elements) => {
                    return <blockquote className={cx(this.context, 'blockquote')}>{elements.children}</blockquote>
                }
            }
        };

        return (
            <div ref={this.props.htmlRef} className={this.props.className} style={{'overflowWrap': 'break-word'}}>
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
    htmlRef: PropTypes.object,
    trusted: PropTypes.bool
};

export default MarkdownRender;