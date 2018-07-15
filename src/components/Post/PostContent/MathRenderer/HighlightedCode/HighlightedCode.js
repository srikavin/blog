import * as React from 'react';
import Loadable from 'react-loadable';
import {DynamicLoading} from '../../../../DynamicLoading/DynamicLoading';

const SyntaxHighlighter = Loadable({
    loader: () => import(/* webpackChunkName: "code-highlighter" */'react-syntax-highlighter'),
    loading: DynamicLoading
});
const docco = Loadable({
    loader: () => import(/* webpackChunkName: "code-highlight-style" */'react-syntax-highlighter/styles/hljs').docco,
    loading: DynamicLoading
});


class HighlightedCode extends React.Component {
    displayName = 'CodeBlock';

    render() {
        return (
            <SyntaxHighlighter language={this.props.language}
                               style={docco}>{this.props.value ? this.props.value : ''}</SyntaxHighlighter>
        );
    }
}

export default HighlightedCode;

