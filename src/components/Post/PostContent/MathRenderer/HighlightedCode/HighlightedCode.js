import * as React from 'react';
import docco from 'react-syntax-highlighter/dist/styles/hljs/docco';
import SyntaxHighlighter, {registerLanguage} from 'react-syntax-highlighter/dist/light';
import './HighlightedCode.module.css'

class HighlightedCode extends React.Component {
    displayName = 'CodeBlock';

    defaults = {
        'show-line-numbers': true
    };

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
            import(/* webpackChunkName: "code-highlighter-[request]" */'react-syntax-highlighter/dist/languages/hljs/' + lang).then(e => {
                registerLanguage(lang, e.default);
                this.forceUpdate();
            }).catch(console.log)
        }
    }

    render() {
        let settings;
        if (this.props.settings && !this.props.inline) {
            settings = Object.assign({}, this.defaults, this.props.settings);
        }
        if (this.props.inline) {
            return (
                <SyntaxHighlighter customStyle={{'display': 'inline'}} showLineNumbers={false}
                                   language={this.props.language}
                                   style={docco}>{this.props.value ? this.props.value : ''}</SyntaxHighlighter>
            )
        }
        return (
            <SyntaxHighlighter showLineNumbers={settings['show-line-numbers']} language={this.props.language}
                               style={docco}>{this.props.value ? this.props.value : ''}</SyntaxHighlighter>
        );
    }
}

export default HighlightedCode;

