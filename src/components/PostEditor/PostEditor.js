import React from 'react';
import PropTypes from 'prop-types';

import {css, StyleSheet} from 'aphrodite';
import MarkdownEditor from './MarkdownEditor/MarkdownEditor';
import {Button, ButtonGroup, NonIdealState} from '@blueprintjs/core';
import {IconNames} from '@blueprintjs/icons';
import TagEditor from './TagEditor/TagEditor';
import TitleEditor from './TitleEditor/TitleEditor';

import './PostEditor.css'
import {Intent} from '@blueprintjs/core/lib/cjs/common/intent';

class PostEditor extends React.Component {
    constructor(props) {
        super(props);
        this.onTitleChange = this.onTitleChange.bind(this);
        this.onTagChange = this.onTagChange.bind(this);
        this.submitButton = this.submitButton.bind(this);
        this.onContentsChange = this.onContentsChange.bind(this);
        this.callSubmitCallback = this.callSubmitCallback.bind(this);

        this.state = {};
        this._setStateFromProps(props);
    }

    UNSAFE_componentWillReceiveProps(nextProps, nextContext) {
        this._setStateFromProps(nextProps);
    }

    _setStateFromProps(props) {
        if (!props.post) {
            return;
        }
        this.setState({
            title: props.post.title,
            tags: props.post.tags,
            contents: props.post.contents,
            author: props.post.author,
            slug: props.post.slug,
            ...props.post
        });
    }

    onTitleChange(e) {
        this.setState({
            title: e
        });
    };

    onContentsChange(e) {
        this.setState({
            contents: e
        });
    };

    onTagChange(e) {
        this.setState({
            tags: e
        });
    };

    render() {
        if (this.props.error) {
            return <NonIdealState title={'Unable to edit this post'}
                                  description={'An error occurred while loading the post editor'}
                                  icon={IconNames.ERROR}
            />
        }

        if (this.props.loading || !this.props.post) {
            return 'Loading...';
        }

        return (
            <div className={css(styles.editorContainer)}>
                <ButtonGroup minimal={true} className={css(styles.submitButton)}>
                    {this.submitButton()}
                    <Button onClick={this.callSubmitCallback} icon={IconNames.DOCUMENT} intent={Intent.SUCCESS}>
                        Create Draft
                    </Button>
                </ButtonGroup>
                <TitleEditor title={this.state.title} onTitleChange={this.onTitleChange}/>
                <div className={css(styles.tagEditorContainer)}>
                    <TagEditor tags={this.state.tags} onSelectedChange={this.onTagChange}/>
                </div>
                <MarkdownEditor onChange={this.onContentsChange} value={this.state.contents}/>
            </div>
        )
    }

    callSubmitCallback() {
        let post = {
            ...this.state
        };

        this.props.onSubmit(post);
    }

    submitButton() {
        if (this.props.type === 'update') {
            return (
                <Button icon={IconNames.ADD} onClick={this.callSubmitCallback} intent={Intent.PRIMARY}>Update
                    Post</Button>
            );
        }
        if (this.props.type === 'create') {
            return (
                <Button icon={IconNames.EDIT} onClick={this.callSubmitCallback} intent={Intent.PRIMARY}>Create
                    Post</Button>
            )
        }

        throw new Error('Invalid type, ' + this.props.type + ', given as a prop to PostEditor');
    }
}

const styles = StyleSheet.create({
    editorContainer: {
        position: 'relative',
        marginTop: '20px',
        height: '100%'
    },
    submitButton: {
        position: 'absolute',
        top: '5px',
        right: '5px'
    },
    tagEditorContainer: {
        display: 'flex',
        justifyContent: 'center',
        alignItems: 'center',
        marginBottom: '25px'
    }
});

PostEditor.propTypes = {
    type: PropTypes.oneOf(['update', 'create']).isRequired,
    onSubmit: PropTypes.func.isRequired,
    post: PropTypes.object.isRequired,
    onSubmitDraft: PropTypes.func,
    loading: PropTypes.bool,
    error: PropTypes.bool
};

export default PostEditor;
