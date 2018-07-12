import * as React from 'react';
import SyntaxHighlighter from 'react-syntax-highlighter';
import {docco} from 'react-syntax-highlighter/styles/hljs';

class HighlightedCode extends React.Component {
    displayName = 'CodeBlock';

    render() {
        return (
            <SyntaxHighlighter language={this.props.language} style={docco}>{this.props.value}</SyntaxHighlighter>
        );
    }
}

export default HighlightedCode;

