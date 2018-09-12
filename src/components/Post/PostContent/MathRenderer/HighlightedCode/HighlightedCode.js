import * as React from 'react';
import {docco} from 'react-syntax-highlighter/styles/hljs';
import SyntaxHighlighter, {registerLanguage} from 'react-syntax-highlighter/light';


class HighlightedCode extends React.Component {
    displayName = 'CodeBlock';

    constructor(props) {
        super(props);
        this.loadLanguage();
    }


    componentDidUpdate(prevProps) {
        if (this.props.language !== prevProps.language) {
            this.loadLanguage();
        }
    }

    loadLanguage() {
        if (this.props.language && this.props.language !== null) {
            let lang = this.props.language.toLowerCase();
            import('react-syntax-highlighter/languages/hljs/' + lang).then(e => {
                registerLanguage(lang, e.default);
                this.forceUpdate();
            });
        }
    }

    render() {
        return (
            <SyntaxHighlighter language={this.props.language}
                               style={docco}>{this.props.value ? this.props.value : ''}</SyntaxHighlighter>
        );
    }
}

export default HighlightedCode;

