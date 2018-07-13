import React from 'react';
import PropTypes from 'prop-types';
import {css, StyleSheet} from 'aphrodite';
import ReactMde from 'react-mde';
import 'react-mde/lib/styles/css/react-mde-all.css';
import MathRenderer from '../../Post/PostContent/MathRenderer/MathRenderer';
import SplitPane from 'react-split-pane';
import isEqual from 'react-fast-compare';


class MarkdownEditor extends React.Component {
    constructor(props) {
        super(props);
        this.state = {
            mdeState: {
                markdown: props.value
            }
        };
        this.handleValueChange = this.handleValueChange.bind(this);
    }

    shouldComponentUpdate(nextProps, nextState, nextContext) {
        return this.props.value !== this.state.mdeState.markdown || !isEqual(this.state.mdeState, nextState.mdeState);
    }

    handleValueChange(mdeState) {
        this.setState({mdeState});
        this.props.onChange(mdeState.markdown);
    };

    render() {
        return (
            <SplitPane className={css(styles.container)} split="vertical" minSize={250} defaultSize="50%"
                       primary="second">
                <div className={css(styles.scrollable)}>
                    <ReactMde
                        layout="noPreview"
                        onChange={this.handleValueChange}
                        editorState={this.state.mdeState}
                    />
                </div>
                <div className={css(styles.scrollable)}>
                    <MathRenderer source={this.state.mdeState.markdown}/>
                </div>
            </SplitPane>
        );
    }
}

MarkdownEditor.propTypes = {
    onChange: PropTypes.func,
    value: PropTypes.string.isRequired
};

const styles = StyleSheet.create({
    hidden: {
        display: 'none'
    },
    container: {
        overflow: 'auto'
    },
    scrollable: {
        overflowY: 'scroll',
        marginLeft: '15px',
        marginRight: '15px',
        height: '100%'
    }
});

export default MarkdownEditor;
