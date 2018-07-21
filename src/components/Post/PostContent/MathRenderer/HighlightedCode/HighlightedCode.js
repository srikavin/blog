import * as React from 'react';
import Loadable from 'react-loadable';
import {DynamicLoading} from '../../../../DynamicLoading/DynamicLoading';
import {docco} from 'react-syntax-highlighter/styles/hljs';

const SyntaxHighlighter = Loadable({
    loader: () => import(/* webpackChunkName: "code-highlighter" */'react-syntax-highlighter'),
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

