import * as React from 'react';
import docco from 'react-syntax-highlighter/styles/hljs/docco';
import SyntaxHighlighter, {registerLanguage} from 'react-syntax-highlighter/light';
import './HighlightedCode.module.css'

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
        if (this.props.language) {
            let lang = this.props.language.toLowerCase();
            import(/* webpackChunkName: "code-highlighter-[request]" */'react-syntax-highlighter/languages/hljs/' + lang).then(e => {
                registerLanguage(lang, e.default);
                this.forceUpdate();
            });
        }
    }

    render() {
        if (this.props.inline) {
            return (
                <SyntaxHighlighter customStyle={{'display': 'inline'}} showLineNumbers={false}
                                   language={this.props.language}
                                   style={docco}>{this.props.value ? this.props.value : ''}</SyntaxHighlighter>
            )
        }
        return (
            <SyntaxHighlighter showLineNumbers={true} language={this.props.language}
                               style={docco}>{this.props.value ? this.props.value : ''}</SyntaxHighlighter>
        );
    }
}

export default HighlightedCode;

