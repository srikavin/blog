import {EditableText, H1} from '@blueprintjs/core';
import PropTypes from 'prop-types';
import React from 'react';

import styles from './TitleEditor.module.css'

class TitleEditor extends React.PureComponent {
    render() {
        return (
            <H1 className={`${styles.titleContainer} ${styles.title}`}>
                <EditableText
                    value={this.props.title}
                    onChange={this.props.onTitleChange}
                    selectAllOnFocus={true} placeholder={'Title'}/>
            </H1>
        );
    }
}

TitleEditor.propTypes = {
    title: PropTypes.string.isRequired,
    onTitleChange: PropTypes.func.isRequired
};

export default TitleEditor;
