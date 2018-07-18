import React, {Component} from 'react';
import PostSnippet from './PostSnippet/PostSnippet';
import {css, StyleSheet} from 'aphrodite';
import PropTypes from 'prop-types';

class PostList extends Component {
    render() {
        return (
            <div className={css(styles.container)}>
                {this.props.posts.map(e => <PostSnippet className={css(styles.preview)} key={e.slug} post={e}/>)}
            </div>
        );
    }
}

const styles = StyleSheet.create({
    container: {
        display: 'flex',
        flexWrap: 'wrap',
        flexDirection: 'row',
        alignItems: 'flex-start',
        marginTop: '15px',
        marginLeft: 'auto',
        marginRight: 'auto',
        width: '90vw',
        '@media (max-width: 600px)': {
            width: '100vw'
        }
    },
    preview: {
        ':hover': {
            boxShadow: '0 2px 2px 0 rgba(0, 0, 0, 0.16), 0 0 0 1px rgba(0, 0, 0, 0.08)'
        },
        boxShadow: '0 2px 2px 0 rgba(0, 0, 0, 0.08), 0 0 0 1px rgba(0, 0, 0, 0.04)',
        position: 'relative',
        margin: 'auto',
        padding: '5px 20px',
        marginBottom: '15px',
        backgroundColor: '#FFFFFF',
        maxWidth: '60vw',
        minWidth: '50vw',
        '@media (max-width: 600px)': {
            width: '100vw',
            maxWidth: '100vw',
            minWidth: '90vw',
            maxHeight: '320px'
        },
        '@media (max-width: 1200px)': {
            maxWidth: '90vw',
            minWidth: '70vw'
        },
        overflow: 'hidden'
    }
});

PostList.propTypes = {
    posts: PropTypes.array.isRequired
};

export default PostList;