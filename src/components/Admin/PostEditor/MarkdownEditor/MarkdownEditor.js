import React from 'react';
import PropTypes from 'prop-types';
import {css, StyleSheet} from 'aphrodite';
import ReactMde from 'react-mde';
import 'react-mde/lib/styles/css/react-mde-all.css';
import MathRenderer from '../../../Post/PostContent/MathRenderer/MathRenderer';
import SplitPane from 'react-split-pane';
import isEqual from 'react-fast-compare';

import './MarkdownEditor.css'
import FileUpload from './FileUpload/FileUpload';
import {Prompt} from 'react-router-dom';
import {
    FaBold,
    FaCode,
    FaHeading,
    FaImage,
    FaItalic,
    FaLink,
    FaListOl,
    FaListUl,
    FaQuoteRight,
    FaStrikethrough,
    FaTasks
} from 'react-icons/fa';

function getFaIcon(name) {
    switch (name) {
        case 'heading':
            return <FaHeading/>;
        case 'bold':
            return <FaBold/>;
        case 'italic':
            return <FaItalic/>;
        case 'strikethrough':
            return <FaStrikethrough/>;
        case 'link':
            return <FaLink/>;
        case 'quote-right':
            return <FaQuoteRight/>;
        case 'code':
            return <FaCode/>;
        case 'image':
            return <FaImage/>;
        case 'list-ul':
            return <FaListUl/>;
        case 'list-ol':
            return <FaListOl/>;
        case 'tasks':
            return <FaTasks/>;
    }
}

class MarkdownEditor extends React.Component {
    constructor(props) {
        super(props);
        this.state = {
            markdown: props.value
        };
        this.handleValueChange = this.handleValueChange.bind(this);
    }

    shouldComponentUpdate(nextProps, nextState, nextContext) {
        return this.props.value !== this.state.markdown || !isEqual(this.state, nextState);
    }

    handleValueChange(mdeState) {
        this.setState(mdeState);
        this.props.onChange(mdeState.markdown);
    };

    render() {
        return (
            <FileUpload>
                <Prompt message="Are you sure you want to leave?"/>
                <SplitPane className={css(styles.container)} split="vertical" minSize={250} defaultSize="50%"
                           primary="second">
                    <div className={css(styles.scrollable)}>
                        <ReactMde
                            buttonContentOptions={{
                                iconProvider: getFaIcon
                            }}
                            layout="noPreview"
                            onChange={this.handleValueChange}
                            editorState={this.state}
                        />
                    </div>
                    <div className={css(styles.scrollable)}>
                        <MathRenderer source={this.state.markdown}/>
                    </div>
                </SplitPane>
            </FileUpload>
        )
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
