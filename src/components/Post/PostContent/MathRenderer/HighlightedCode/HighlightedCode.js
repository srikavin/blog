import * as React from 'react';
import docco from 'react-syntax-highlighter/dist/esm/styles/hljs/docco';
import SyntaxHighlighter from 'react-syntax-highlighter/dist/esm/light';
import styles from './HighlightedCode.module.css'

const registerLanguage = SyntaxHighlighter.registerLanguage;

docco.hljs.padding = '0.17em';

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
            import(/* webpackChunkName: "code-highlighter-[request]" */'react-syntax-highlighter/dist/esm/languages/hljs/' + lang).then(e => {
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
            <div className={styles['code-block']}>
                <SyntaxHighlighter showLineNumbers={settings['show-line-numbers']} language={this.props.language}
                                   style={docco}>{this.props.value ? this.props.value : ''}</SyntaxHighlighter>
            </div>
        );
    }
}

export default HighlightedCode;

