import {EditableText, H1} from '@blueprintjs/core';
import PropTypes from 'prop-types';
import React from 'react';

import styles from './TitleEditor.module.css'

class TitleEditor extends React.Component {
    render() {
        return (
            <H1 className={`${styles.titleContainer} ${styles.title}`}>
                <input
                    type="text"
                    value={this.props.title}
                    onChange={this.props.onTitleChange}
                    placeholder={'Title'}/>
            </H1>
        );
    }
}

TitleEditor.propTypes = {
    title: PropTypes.string.isRequired,
    onTitleChange: PropTypes.func.isRequired
};

export default TitleEditor;
