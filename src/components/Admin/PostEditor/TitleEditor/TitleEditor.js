import {EditableText, H1} from '@blueprintjs/core';
import {css, StyleSheet} from 'aphrodite';
import PropTypes from 'prop-types';
import React from 'react';

class TitleEditor extends React.PureComponent {
    render() {
        return (
            <H1 className={css(styles.titleContainer, styles.title)}>
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

const styles = StyleSheet.create({
    titleContainer: {
        display: 'flex',
        justifyContent: 'center',
        alignItems: 'center'
    },
    title: {
        marginBottom: '15px',
        fontFamily: 'Raleway, sans-serif',
        fontSize: '76px',
        fontWeight: 'lighter'
    }
});